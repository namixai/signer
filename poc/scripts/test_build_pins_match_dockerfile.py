"""
`policies/build-pins.txt` обязан совпадать с тем, что РЕАЛЬНО собирает EIF.

ЗАЧЕМ ЭТОТ ГЕЙТ. `build-pins.txt` — auditor-facing поверхность: на него как на
«recorded pins» указывают публичные `VERIFY-SIGNER-YOURSELF.md` и
`REPRODUCIBLE-BUILD.md`, и внешний аудитор берёт значения ОТТУДА, чтобы
пересобрать байт-идентичный образ и сверить PCR0. Сам файл объявляет цель:
«every dependency and base image is pinned… so two clean builds produce
byte-identical EIF».

Гарантию давал комментарий («cross-reference policies/build-pins.txt» в трёх
местах Dockerfile) — и не дал: на 2026-08-26 файл разошёлся с деревом в ТРЁХ
местах, а не в одном, как считала разведка (она сравнивала только с Dockerfile
и не смотрела rust-toolchain.toml):

  · clux_muslrust_digest       — образ подняли 1.83 → 1.95, пин остался старым;
  · aws_nitro_enclaves_sdk_c   — Dockerfile:106 клонирует другой коммит;
  · rust_enclave               — rust-toolchain.toml переехал на 1.95.0.

Каждое расхождение стоит одинаково: аудитор либо соберёт НЕ ТОТ образ (и «byte-
identical» окажется тихой ложью), либо упрётся в digest, который реестр уже
почистил, — ровно в тот момент, когда мы пообещали «просто повтори».

ЧТО ПРОВЕРЯЕТСЯ. Каждый пин сверяется с ЕГО ИСТОЧНИКОМ в дереве. Соответствие
ОБЪЯВЛЕНО таблицей ниже, а не выведено из имени: `aws_c_common` → `AWS_C_COMMON_REF`
угадывается, а `aws_nitro_enclaves_nsm_api` → `AWS_NITRO_NSM_API_REF` уже нет, и
правило, которое угадывает, молча пропустит именно тот пин, который переименовали.
Плюс обратная сторона: каждый `ARG *_REF` в Dockerfile обязан быть в таблице —
новый пин, о котором файл не знает, роняет гейт, а не остаётся незаписанным.

Только stdlib, ни сети, ни docker: это сверка текстов в репозитории, и она
обязана работать на PR, а не в окне.
"""
import re
import sys
from pathlib import Path

POC = Path(__file__).resolve().parents[1]
PINS = POC / "policies" / "build-pins.txt"
DOCKERFILE = POC / "enclave" / "Dockerfile"
TOOLCHAIN = POC / "rust-toolchain.toml"

# пин → ARG в Dockerfile. Объявлено, не выведено.
ARG_OF = {
    "aws_lc": "AWS_LC_REF",
    "s2n_tls": "S2N_TLS_REF",
    "aws_c_common": "AWS_C_COMMON_REF",
    "aws_c_sdkutils": "AWS_C_SDKUTILS_REF",
    "aws_c_cal": "AWS_C_CAL_REF",
    "aws_c_io": "AWS_C_IO_REF",
    "aws_c_compression": "AWS_C_COMPRESSION_REF",
    "aws_c_http": "AWS_C_HTTP_REF",
    "aws_c_auth": "AWS_C_AUTH_REF",
    "json_c": "JSON_C_REF",
    "aws_nitro_enclaves_nsm_api": "AWS_NITRO_NSM_API_REF",
    "aws_nitro_enclaves_sdk_c": "AWS_NITRO_SDK_C_REF",
}

# ARG'и Dockerfile, которые пином быть НЕ обязаны — с причиной у каждого.
# Список явный: «неизвестный ARG» обязан ронять гейт, а не тихо выпадать.
ARGS_NOT_PINNED = {
    # Флаг сборки, а не версия зависимости: он не влияет на то, ЧТО скачано,
    # он влияет на поведение бинаря (strict-режим политики).
    "SIGNER_REQUIRE_POLICY",
}

# Ключи build-pins.txt, у которых источник истины НЕ в Dockerfile.
# Каждый — со своим извлекателем, потому что «пин без источника» — это пин,
# который никто не сверит.
def _dockerfile() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def _toolchain_channel() -> str:
    m = re.search(r'^\s*channel\s*=\s*"([^"]+)"', TOOLCHAIN.read_text(encoding="utf-8"), re.M)
    _need(m, f"в {TOOLCHAIN} нет `channel = \"…\"`")
    return m.group(1)


def _muslrust_digest() -> str:
    m = re.search(r"^FROM\s+clux/muslrust@(sha256:[0-9a-f]{64})", _dockerfile(), re.M)
    _need(m, "в Dockerfile нет `FROM clux/muslrust@sha256:…`")
    return m.group(1)


def _amazonlinux_digest() -> str:
    got = set(re.findall(
        r"^FROM\s+public\.ecr\.aws/amazonlinux/amazonlinux@(sha256:[0-9a-f]{64})",
        _dockerfile(), re.M))
    _need(got, "в Dockerfile нет `FROM …/amazonlinux@sha256:…`")
    # Dockerfile обещает «same digest as kmstool-builder» — обещание проверяем.
    _need(len(got) == 1, f"стадии amazonlinux разъехались по digest: {sorted(got)}")
    return got.pop()


def _kmstool_rust() -> str:
    """Версия тулчейна kmstool — из АКТИВНЫХ строк Dockerfile, не из комментариев.

    🔴 Замерено 14.09, и промах был в опасную сторону. Поиск шёл по всему тексту, и
    устаревший комментарий со значением, совпадающим с пином, ЗАТЕНЯЛ активную строку:
    Dockerfile собирал на `9.9.9`, `build-pins.txt` говорил `1.92.0`, а гейт печатал
    «5/5 passed». То есть проверка, заведённая ловить тихое расхождение, сама тихо его
    пропускала — прозу принимала за механизм. Найдено ревью CodeRabbit на #101.

    Активных значений должно быть ровно одно: две разные версии в живых строках — это
    не «возьмём первую», а расхождение, о котором надо сказать.
    """
    got = {
        m.group(1)
        for line in _dockerfile().splitlines()
        if not line.lstrip().startswith("#")
        for m in [re.search(r"--default-toolchain\s+([0-9][0-9.]*)", _strip_inline_comment(line))]
        if m
    }
    _need(got, "в Dockerfile нет активной строки `--default-toolchain <версия>`")
    _need(len(got) == 1,
          f"в активных строках Dockerfile несколько версий тулчейна kmstool: {sorted(got)}")
    return got.pop()


def _strip_inline_comment(line: str) -> str:
    """Отрезать хвостовой `#…`, не трогая решётки внутри кавычек.

    Без этого `RUN foo   # --default-toolchain 1.70.0` снова затенял бы активное
    значение — тем же способом, только на одной строке.
    """
    out, quote = [], None
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            continue
        if ch == "#":
            break
        out.append(ch)
    return "".join(out)


NON_DOCKERFILE_PINS = {
    "clux_muslrust_digest": _muslrust_digest,
    "amazonlinux_2_digest": _amazonlinux_digest,
    "rust_enclave": _toolchain_channel,
    "rust_kmstool_nsm_lib": _kmstool_rust,
}

# Ключи, у которых источника в дереве нет по природе: это записи о ПРОЦЕДУРЕ
# вендоринга (что склонировали, куда положили, сколько весит), а не пины того,
# что скачивает сборка. Список явный по той же причине, что и ARGS_NOT_PINNED.
PINS_WITHOUT_TREE_SOURCE = {
    "nsm_api_upstream_tag_sha", "nsm_api_actual_commit_sha", "nsm_api_upstream_version",
    "nsm_api_vendored_path", "nsm_api_vendored_crate_count", "nsm_api_vendored_size",
    "nsm_api_lockfile_size", "nsm_api_cargo_resolver_version", "nsm_api_compatible_rust",
}

YUM_PIN = re.compile(r"^yum_[a-z0-9_]+$")


class GateFailure(AssertionError):
    """Провал проверки. Наследник AssertionError — чтобы существующие раннеры,
    ловящие его, продолжали работать."""


def _need(cond, msg: str) -> None:
    """Проверка, ПЕРЕЖИВАЮЩАЯ `python -O`.

    Голый `assert` под `-O` вырезается целиком: гейт напечатал бы `ok` по всем
    тестам, ничего не сверив, — худший режим отказа для гейта (CodeRabbit).
    """
    if not cond:
        raise GateFailure(msg)


def pins() -> dict:
    out = {}
    for n, line in enumerate(PINS.read_text(encoding="utf-8").splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^([a-z0-9_]+)=(\S+)", s)
        _need(m, f"{PINS.name}:{n}: не разобрана строка пина: {s!r}")
        key, value = m.group(1), m.group(2)
        # Дубль ключа тихо переписывался последним значением: устаревшая строка
        # выше + совпадающая ниже давали ЗЕЛЁНЫЙ гейт над файлом, в котором
        # аудитор читает первое попавшееся (CodeRabbit).
        _need(key not in out,
              f"{PINS.name}:{n}: ключ {key} объявлен дважды "
              f"(было {out.get(key)!r}, стало {value!r})")
        out[key] = value
    return out


def test_pins_file_parses_and_is_not_empty():
    p = pins()
    _need(len(p) >= 25, f"пинов подозрительно мало ({len(p)}) — файл не разобран?")


def test_every_dockerfile_ref_arg_is_pinned():
    """Новый ARG без пина — незаписанная зависимость на auditor-facing поверхности."""
    # ИМЕНА берутся и у `ARG NAME=value`, и у `ARG NAME` без дефолта: второй
    # подставляется при сборке (`--build-arg`), то есть тоже определяет, что
    # скачано, и мимо манифеста проходил незамеченным (CodeRabbit).
    names = set(re.findall(r"^ARG\s+([A-Z0-9_]+)", _dockerfile(), re.M))
    known = set(ARG_OF.values()) | ARGS_NOT_PINNED
    unknown = sorted(names - known)
    _need(not unknown,
          "в Dockerfile появились ARG, которых нет ни в таблице пинов, ни в списке "
          f"осознанно непинуемых: {', '.join(unknown)}.\n"
          "Добавь пин в policies/build-pins.txt и строку в ARG_OF — либо, если это "
          "флаг сборки, впиши его в ARGS_NOT_PINNED с причиной.")


def test_every_pin_matches_its_source_in_the_tree():
    p = pins()
    df_args = dict(re.findall(r"^ARG\s+([A-Z0-9_]+)\s*=\s*(\S+)", _dockerfile(), re.M))

    # 🔴 СНАЧАЛА — что пин вообще есть. Цикл ниже идёт по ключам, КОТОРЫЕ ОСТАЛИСЬ в
    # файле, поэтому удалённый пин не сверялся ни с чем и гейт оставался зелёным.
    # Замерено 14.09: убрать строку `rust_enclave=` из манифеста — 5/5 passed, при том
    # что манифест аудитора потерял зависимость сборки. Отсутствие голосовало за успех
    # ровно там, где файл читается как истина. Найдено ревью CodeRabbit на #101.
    expected = set(NON_DOCKERFILE_PINS) | set(ARG_OF)
    missing = sorted(k for k in expected if k not in p)
    _need(not missing,
          "пины, для которых в дереве есть источник, ПРОПАЛИ из build-pins.txt: "
          + ", ".join(missing)
          + ". Аудитор читает этот файл как полный список зависимостей сборки; "
            "молчаливая недостача здесь — это не пустое место, а неверный список.")

    mismatched, unsourced = [], []
    for key, value in sorted(p.items()):
        if key in PINS_WITHOUT_TREE_SOURCE or YUM_PIN.match(key):
            continue
        if key in NON_DOCKERFILE_PINS:
            actual = NON_DOCKERFILE_PINS[key]()
            where = "rust-toolchain.toml" if key == "rust_enclave" else "enclave/Dockerfile"
        elif key in ARG_OF:
            arg = ARG_OF[key]
            if arg not in df_args:
                # Две разные беды с одним следствием: ARG переименовали/удалили,
                # ЛИБО у него убрали дефолт (значение приходит `--build-arg`).
                # Во втором случае пин сверить не с чем — и «не смог сверить»
                # обязано отказывать, а не молчать: аудитор читает этот файл
                # как истину.
                present = arg in re.findall(r"^ARG\s+([A-Z0-9_]+)", _dockerfile(), re.M)
                unsourced.append(
                    f"{key}: ARG {arg} " + (
                        "объявлен БЕЗ дефолта (значение приходит --build-arg) — "
                        "сверить пин не с чем"
                        if present else "исчез из Dockerfile"))
                continue
            actual, where = df_args[arg], f"enclave/Dockerfile ARG {arg}"
        else:
            unsourced.append(f"{key}: нет источника — ни ARG, ни явного извлекателя")
            continue
        if value != actual:
            mismatched.append(f"  {key}\n    build-pins.txt: {value}\n    {where}: {actual}")
    _need(not unsourced,
          "пин без источника — это пин, который никто не сверит:\n  " + "\n  ".join(unsourced))
    _need(not mismatched,
          "policies/build-pins.txt разошёлся с тем, что реально собирает EIF.\n"
          "Внешний аудитор соберёт НЕ ТОТ образ, а «byte-identical» станет тихой "
          "ложью:\n" + "\n".join(mismatched))


def dockerfile_yum_packages() -> set:
    """Явный список пакетов из `RUN yum install` — разобранный, а не найденный
    подстрокой. Подстрочный поиск по всему файлу засчитывал и ЗАКОММЕНТИРОВАННУЮ
    строку, и упоминание в прозе: пакет, снятый с установки, продолжал бы
    «подтверждать» свой пин (CodeRabbit)."""
    df = _dockerfile()
    # 🔴 findall, не search: `search` брал ТОЛЬКО ПЕРВЫЙ блок, и вторая стадия сборки со
    # своим `RUN yum install` осталась бы непроверенной — пакет, добавленный туда,
    # никогда бы не сверился с пином. Сегодня блок один (замерено), и это ровно та
    # причина, по которой дефект не виден: он ждёт второй стадии. Найдено ревью Gemini
    # на #101.
    blocks = re.findall(r"^RUN\s+yum\s+install\b(.*?)(?=^\s*$|^[A-Z]+\s)", df, re.M | re.S)
    _need(blocks, "в Dockerfile не найден блок `RUN yum install`")
    out = set()
    for raw in "\n".join(blocks).splitlines():
        line = raw.split("#", 1)[0].replace("\\", " ")
        for tok in line.split():
            if tok in {"-y", "&&", "yum", "clean", "all", "install"} or tok.startswith("-"):
                continue
            out.add(tok)
    _need(out, "блок `RUN yum install` разобран пустым")
    return out


def test_yum_pins_and_dockerfile_agree_exactly():
    """В ОБЕ стороны: незаписанный пакет так же слеп, как записанный лишний."""
    pinned = {v for k, v in pins().items() if YUM_PIN.match(k)}
    requested = dockerfile_yum_packages()
    only_pinned = sorted(pinned - requested)
    only_docker = sorted(requested - pinned)
    _need(not only_pinned,
          "yum-пины записаны, но Dockerfile их не запрашивает:\n  " + "\n  ".join(only_pinned))
    _need(not only_docker,
          "Dockerfile ставит пакеты, которых нет в build-pins.txt — аудитор соберёт "
          "не то:\n  " + "\n  ".join(only_docker))


def test_the_gate_is_actually_looking_at_something():
    """Контроль: гейт был бы зелёным и на пустом Dockerfile."""
    _need(PINS.is_file() and DOCKERFILE.is_file() and TOOLCHAIN.is_file(),
          "один из трёх источников не найден на диске")
    _need(len(ARG_OF) >= 12, "таблица источников усохла — гейт перестал покрывать пины")
    args = re.findall(r"^ARG\s+([A-Z0-9_]+)", _dockerfile(), re.M)
    _need(len(args) >= 12, f"в Dockerfile найдено {len(args)} ARG — файл прочитан не тот")


def main() -> int:
    failed = 0
    tests = sorted((n, f) for n, f in globals().items()
                   if n.startswith("test_") and callable(f))
    for name, fn in tests:
        try:
            fn()
            print(f"ok   {name}")
        except Exception as e:  # noqa: BLE001
            # Ловим ВСЁ, а не только AssertionError: переехавший файл даёт
            # FileNotFoundError, и он прерывал бы прогон — остальные пины
            # оставались бы несверенными, а вывод не сказал бы, какие именно.
            failed += 1
            print(f"FAIL {name}\n{e if isinstance(e, AssertionError) else repr(e)}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
