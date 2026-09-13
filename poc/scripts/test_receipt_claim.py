#!/usr/bin/env python3
"""The README's receipt promise, held against the handlers that keep it.

🔴 Why. README.md said "Every signed call returns a Verifiable Policy Proof". Measured
2026-09-13: `/sign/data` is a signed call and returns none — the word `receipt` does not
appear once in `post_sign_data` (lines 898–1073). The claim was wider than the mechanism,
in the file a judge reads first, and nothing checked it, so it drifted quietly.

It also drifted in the other direction for a while inside my own head: I first reported
that no cancel route issues receipts, because I grepped `take_receipt` inside each handler
body and did not follow `sign_structured_request`, which calls it once for all six
structured callers. Checking a LIST OF PLACES instead of a PROPERTY is the same mistake
the claim itself made. So this test follows both paths to the receipt, not one.

What it enforces: the set of signing routes that carry a receipt, and the exception list
printed in the README, must agree. A new `/sign/…` route with no receipt fails here until
the README names it. Removing an exception from the README while the route still lacks a
receipt fails too.

Standard library only. No network, no gateway, no build.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HANDLERS = ROOT / "poc" / "gateway" / "src" / "handlers.rs"
README = ROOT / "README.md"

# Routes the promise is about: they ask the enclave to sign or decide. Reads, health,
# blob verification and the heartbeat are not "signed calls" and are out of scope —
# naming them here rather than leaving the scope to a reader's guess.
NOT_A_SIGNING_CALL = {
    "get_healthz", "post_verify_blob", "post_receipt_heartbeat",
    "get_attestation", "get_account", "get_open_orders", "get_user_trades",
}


def _result_ok_type(signature: str):
    """Ok-часть `Result<Ok, Err>` — со скобочным балансом, а не «до первой запятой».

    🔴 Первая версия брала `[^,]+` и на типе `Result<(Map, ReceiptValue), Response>`
    захватывала `(std::collections::BTreeMap<String` — мутация «тип успеха понёс
    квитанцию» её НЕ покрасила. Нашёл собственной мутацией сразу после того, как
    написал проверку; вложенные `<>` и `()` здесь обычное дело, и наивный разбор
    молча отвечает не на тот вопрос.
    """
    i = signature.find("-> Result<")
    if i == -1:
        return None
    i += len("-> Result<")
    depth, start = 0, i
    while i < len(signature):
        c = signature[i]
        if c in "<([":
            depth += 1
        elif c in ">)]":
            if depth == 0:            # закрылся сам Result — запятой верхнего уровня не было
                return None
            depth -= 1
        elif c == "," and depth == 0:
            return signature[start:i]
        i += 1
    return None


def strip_noncode(text: str) -> str:
    """Blank out comments, string literals and raw strings, keeping line structure.

    🔴 Why this is not fussiness. The matcher looked for `take_receipt(` in RAW text, so a
    handler with no receipt whose COMMENT mentioned the call was classified as carrying
    one — and CI then stopped demanding that the route be named in the README. Measured:
    one inserted comment line in `post_sign_data` emptied the "lacks" set entirely. That
    is "the diagnostic decides the outcome", moved into code parsing: prose taken for
    mechanism, in the guard whose whole job is catching prose that outruns mechanism.

    Newlines are preserved so line-based splitting downstream keeps working.
    """
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        # raw string: r"…" / r#"…"# / r##"…"##
        if c == "r" and i + 1 < n and (text[i + 1] == '"' or text[i + 1] == "#"):
            j = i + 1
            hashes = 0
            while j < n and text[j] == "#":
                hashes += 1
                j += 1
            if j < n and text[j] == '"':
                close = '"' + "#" * hashes
                k = text.find(close, j + 1)
                k = n if k == -1 else k + len(close)
                out.append("".join(ch if ch == "\n" else " " for ch in text[i:k]))
                i = k
                continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            depth, j = 1, i + 2           # Rust block comments nest
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1; j += 2
                elif text.startswith("*/", j):
                    depth -= 1; j += 2
                else:
                    j += 1
            out.append("".join(ch if ch == "\n" else " " for ch in text[i:j]))
            i = j
            continue
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            out.append("".join(ch if ch == "\n" else " " for ch in text[i:j]))
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _functions(src_lines):
    """Every fn in the file, private ones included, mapped to its body.

    🔴 Cut at `mod tests` first. The LAST handler's body otherwise runs to EOF and
    swallows the test module, which mentions `sign_structured_request` twice — enough to
    classify `post_cancel_all` as carrying a receipt on the strength of test comments.
    Measured: its real body (3990–4102) contains neither marker. Raised by review on #100,
    and the parser was right about that route only by accident.
    """
    cut = next((i for i, l in enumerate(src_lines) if l.strip().startswith("mod tests")),
               len(src_lines))
    code = src_lines[:cut]
    sig = re.compile(r"^\s*(?:pub(?:\(crate\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)")
    starts = [(i, m.group(1)) for i, l in enumerate(code) if (m := sig.match(l))]
    out = {}
    for n, (i, name) in enumerate(starts):
        j = starts[n + 1][0] if n + 1 < len(starts) else len(code)
        out[name] = "\n".join(code[i:j])
    return out, [name for _, name in starts]


def _reaches_receipt(name, fns, seen=None):
    """Does this function reach `take_receipt`, directly or through what it calls?

    The receipt is reached by three different paths in this file — a direct call, the
    structured helper, and the account-read helper — and following only the first two is
    how I mis-reported cancels once already. So this walks the call graph instead of
    matching two names.
    """
    seen = seen or set()
    if name in seen or name not in fns:
        return False
    seen.add(name)
    body = fns[name]
    if "take_receipt(" in body:
        return True
    for callee in set(re.findall(r"\b([a-z][A-Za-z0-9_]*)\s*\(", body)):
        if callee != name and callee in fns and _reaches_receipt(callee, fns, seen):
            return True
    return False


def handlers_with_receipt(source: str | None = None):
    """(carries, lacks) — handler names, split by whether a receipt can reach a response.

    `source` lets the fixtures below drive this over synthetic Rust; production callers
    pass nothing and get the real gateway.
    """
    raw = source if source is not None else HANDLERS.read_text(encoding="utf-8",
                                                               errors="replace")
    src = strip_noncode(raw).splitlines()
    fns, order = _functions(src)
    handlers = [n for n in order if n.startswith(("post_", "get_"))
                and re.search(rf"pub async fn {re.escape(n)}\b", fns[n])]
    if not handlers:
        raise AssertionError(f"{HANDLERS}: no `pub async fn` handlers found — the file "
                             f"moved or changed shape, and this guard is checking nothing")
    carries, lacks = set(), set()
    for name in handlers:
        if name in NOT_A_SIGNING_CALL:
            continue
        (carries if _reaches_receipt(name, fns) else lacks).add(name)
    return carries, lacks


def exceptions_named_in_readme():
    """Handler names the README admits have no receipt — read from an explicit marker.

    🔴 NOT parsed out of the prose. The first version of this function looked for the
    route string near the words "no" and "receipt", and a mutation that deleted the
    exception from the page left it GREEN, because the route still appeared in a third
    sentence that happened to contain both words. A guard that guesses at English passes
    when it should not — which is the exact defect class this file exists to catch, so it
    had no business being inside it. The page now carries one machine-readable line and
    this reads that.
    """
    text = README.read_text(encoding="utf-8")
    if "Verifiable Policy Proof" not in text:
        raise AssertionError("README no longer mentions the Verifiable Policy Proof — if "
                             "the claim was dropped, retire this file rather than leaving "
                             "it green against nothing")
    m = re.search(r"<!--\s*receipt-exceptions:([^>]*?)-->", text)
    if not m:
        raise AssertionError(
            "README has no `<!-- receipt-exceptions: … -->` marker. The prose alone cannot "
            "be checked without guessing at English; add the marker next to the exception "
            "paragraph and keep the two in step.")
    return {w for w in m.group(1).split() if w.startswith("post_")}


class ReceiptClaimTest(unittest.TestCase):
    def test_readme_names_every_signing_route_that_has_no_receipt(self):
        carries, lacks = handlers_with_receipt()
        self.assertTrue(carries, "no handler carries a receipt — detection is broken, and "
                                 "a broken detector would pass every other case here")
        named = exceptions_named_in_readme()
        unnamed = lacks - named
        self.assertFalse(
            unnamed,
            f"these signing routes return no receipt and the README does not say so: "
            f"{sorted(unnamed)}. The promise would be wider than the mechanism — narrow "
            f"the claim or give the route a receipt.")

    def test_cancel_all_stays_named(self):
        """🔴 Страж обязан держать КАЖДОЕ исключение, а не одно из двух.

        Измерено до правки: убрать `post_cancel_all` из маркера — оба теста зелёные.
        Причина в том, что `test_named_exceptions_are_really_exceptions` утверждал только
        `post_sign_data`, а разборщик ветки не видит: `/cancel-all` доходит до квитанции
        через `sign_account_read`, поэтому попадает в «несут» и не требует упоминания.
        Значит клейм, ради которого написан файл, держался наполовину.
        """
        named = exceptions_named_in_readme()
        self.assertIn(
            "post_cancel_all", named,
            "README перестал называть /cancel-all среди исключений, а его УСПЕШНЫЙ путь "
            "квитанции не несёт — проверено отдельным случаем ниже")

    def test_account_read_returns_a_receipt_only_on_refusal(self):
        """По-веточный факт, на который опирается формулировка про /cancel-all.

        `sign_account_read` — единственный путь к квитанции у /cancel-all и у чтений.
        Он вкладывает её в `Err(...)`; на успехе возвращает одни заголовки.

        🔴 Следим за ЗНАЧЕНИЕМ, а не за именем. Первая версия искала слово `receipt` в
        строках вне `Err(` — и переименование `let receipt` в `let decision` с утечкой на
        успех оставляло её ЗЕЛЁНОЙ. Проверено мутацией. Тот же класс, что весь этот файл
        ловит: совпадение имён вместо свойства, теперь в третий раз и в моём же коде.

        Две независимые опоры:
          1. имя, которому присвоен результат `take_receipt(...)`, встречается только в
             возвратах `Err(...)`;
          2. тип успеха у функции не несёт квитанции вовсе — что бы ни назвали внутри,
             на успехе наружу уходит карта заголовков, и провести квитанцию можно только
             сменив сигнатуру, а её мы и проверяем.
        """
        src = strip_noncode(HANDLERS.read_text(encoding="utf-8", errors="replace"))
        fns, _ = _functions(src.splitlines())
        self.assertIn("sign_account_read", fns,
                      "sign_account_read исчез — путь к квитанции у /cancel-all изменился, "
                      "и формулировку в README надо перепроверить руками")
        body = fns["sign_account_read"]
        self.assertIn("take_receipt(", body, "sign_account_read больше не берёт квитанцию")

        # (1) чьё имя держит квитанцию — берём из самого присваивания, не угадываем
        m = re.search(r"let\s+(?:mut\s+)?([A-Za-z0-9_]+)\s*=\s*take_receipt\(", body)
        self.assertIsNotNone(
            m, "результат take_receipt() больше не присваивается имени — форма изменилась, "
               "и следить за значением этим способом нельзя; перепроверьте руками")
        held = m.group(1)
        offenders = [line.strip() for line in body.splitlines()
                     if re.search(rf"\b{re.escape(held)}\b", line)
                     and "Err(" not in line and "take_receipt(" not in line]
        self.assertFalse(
            offenders,
            f"значение квитанции (`{held}`) используется вне ветки Err: {offenders}. "
            f"Если оно уходит и на успехе, README про «/cancel-all не выдаёт на успехе» "
            f"стал неверен")

        # (2) и вторая опора, независимая от имён: тип успеха
        sig = body[:body.index("{")] if "{" in body else body
        ok_type = _result_ok_type(sig)
        self.assertIsNotNone(ok_type, f"не разобрал сигнатуру sign_account_read: {sig[:120]}")
        self.assertNotIn(
            "receipt", ok_type.lower(),
            f"тип успеха sign_account_read стал нести квитанцию ({ok_type.strip()}) "
            f"— формулировку в README надо менять")

    def test_a_comment_is_not_a_call(self):
        """🔴 Фикстура на класс «текст принят за механизм».

        Обработчик без квитанции, у которого нужные слова стоят в комментарии, в строковом
        литерале и в сырой строке Rust. До правки один такой комментарий в `post_sign_data`
        опустошал множество «не несут» целиком.
        """
        fixture = '''
pub async fn post_sign_nothing(State(state): State<AppState>) -> Response {
    // historical note: this used to call take_receipt(&mut resp, customer);
    /* and sign_structured_request( was considered here too */
    let msg = "take_receipt(";
    let raw = r#"sign_structured_request("#;
    error_response(err_code::INTERNAL_ERROR)
}

pub async fn post_sign_really(State(state): State<AppState>) -> Response {
    let receipt = take_receipt(&mut resp, customer);
    Json(Thing { receipt }).into_response()
}
'''
        carries, lacks = handlers_with_receipt(fixture)
        self.assertIn("post_sign_nothing", lacks,
                      "комментарий/литерал засчитан как вызов — текст принят за механизм")
        self.assertIn("post_sign_really", carries,
                      "настоящий вызов перестал распознаваться — стриппер съел код")

    def test_named_exceptions_are_really_exceptions(self):
        """An exception list that outlives the exception is its own kind of false claim."""
        carries, lacks = handlers_with_receipt()
        named = exceptions_named_in_readme()
        # /cancel-all reaches the helper, so it is listed for the SUCCESS branch only;
        # that branch is not visible to this parser, so it is allowed to appear in either
        # set. /sign/data must genuinely lack one.
        self.assertIn("post_sign_data", lacks,
                      "README names /sign/data as having no receipt, but the handler now "
                      "reaches one — remove the exception, do not leave the page claiming "
                      "a hole that was filled")
        self.assertIn("post_sign_data", named,
                      "the README stopped naming /sign/data while the route still has no "
                      "receipt")

    def test_the_money_path_all_carries_receipts(self):
        """The positive half: without it, deleting every receipt would pass the tests above."""
        carries, _ = handlers_with_receipt()
        for name in ["post_sign", "post_sign_binance_order", "post_sign_binance_cancel",
                     "post_sign_okx_order", "post_sign_okx_cancel",
                     "post_sign_binance_spot_order", "post_sign_binance_spot_cancel"]:
            with self.subTest(handler=name):
                self.assertIn(name, carries,
                              f"{name} no longer reaches a receipt — the money-path half "
                              f"of the README's promise is now false")


if __name__ == "__main__":
    unittest.main(verbosity=2)
