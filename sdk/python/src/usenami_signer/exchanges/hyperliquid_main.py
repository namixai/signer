"""Hyperliquid mainnet (EIP-712 family) exchange wrapper.

Hyperliquid is the canonical L1 in the Hyperliquid universe. Phase 1 Stage 2
covers `order` and `cancel` actions; `usdClassTransfer`, `approveAgent`, and
HIP-3 deployer venues (xyz/km/cash/etc) are follow-up briefs.

Unlike the HMAC wrappers (KuCoin/Binance/Bybit/OKX) which sign over an HTTP
canonical string, Hyperliquid signs over an EIP-712 typed-data digest. The
signature commits to the ACTION BODY directly, so the SDK forwards:

    signer.hyperliquid_main.order(asset_index=0, is_buy=True, price="50000",
                                  size="0.001")

and the gateway returns a `{r, s, v}` triple that the SDK then posts to the
Hyperliquid HTTP API at `https://api.hyperliquid.xyz/exchange` under
`body.signature`.

Per-venue API design (Alex's CTO call): the SDK exposes
`signer.hyperliquid_main.order(...)`, NOT `signer.hyperliquid("main", ...)`.
HIP-3 deployer venues will get their own attributes
(`signer.hyperliquid_xyz`, `signer.hyperliquid_km`, etc.) in follow-up
patches.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from usenami_signer.exchanges.base import BaseExchange


class HyperliquidMainExchange(BaseExchange):
    """Hyperliquid mainnet (`hyperliquid_main`) DEX wrapper.

    Surface area for Phase 1 Stage 2:
      - ``order(...)``: place a single order
      - ``cancel(...)``: cancel an open order by ``(asset_index, oid)``

    Internally each method:
      1. Builds the canonical ``action`` JSON with keys sorted as the
         Hyperliquid Python SDK does (the msgpack encoding is order-
         sensitive — see ``signer.rs::msgpack_action`` for context).
      2. Calls ``signer.sign(...)`` with the EIP-712-specific kwargs
         (``kind``, ``action``, ``nonce``).
      3. Receives ``{r, s, v}`` back from the gateway.
      4. POSTs ``{action, nonce, signature, vaultAddress}`` to
         ``https://api.hyperliquid.xyz/exchange``.

    The customer's private key never leaves the AWS Nitro Enclave.
    """

    exchange_name = "hyperliquid_main"
    base_url = "https://api.hyperliquid.xyz"

    def order(
        self,
        *,
        asset_index: int,
        is_buy: bool,
        price: str,
        size: str,
        reduce_only: bool = False,
        order_type: dict[str, Any] | None = None,
        cloid: str | None = None,
        grouping: str = "na",
        vault_address: str | None = None,
        nonce: int | None = None,
    ) -> httpx.Response:
        """Place a single Hyperliquid order.

        Args:
            asset_index: Hyperliquid asset index (0 = BTC on mainnet, etc).
                The mapping is queryable via the public ``meta`` endpoint;
                we do NOT resolve symbol->index here because the mapping
                can change and would tie the SDK to a stale cache.
            is_buy: True for a long, False for a short.
            price: Limit price as a *string* (Hyperliquid is precision-
                sensitive; passing a float would truncate).
            size: Order size as a string, same reasoning.
            reduce_only: If True, won't open a new position.
            order_type: Defaults to ``{"limit": {"tif": "Gtc"}}``. Other
                useful values: ``{"limit": {"tif": "Ioc"}}``,
                ``{"trigger": {"isMarket": True, "triggerPx": "...",
                               "tpsl": "tp"}}`` for take-profit, etc.
            cloid: Optional 16-byte client order id as ``0x``-prefixed hex.
            grouping: ``"na"`` (default) or ``"normalTpsl"`` for batched
                TP/SL.
            vault_address: ``0x``-prefixed 20-byte vault if signing on
                behalf of a vault. ``None`` for the common case.
            nonce: Override nonce (Unix ms). If ``None``, uses
                ``int(time.time() * 1000)``.

        Returns:
            ``httpx.Response`` from ``POST /exchange``. The response body
            is the standard Hyperliquid envelope: ``{"status": "ok",
            "response": {...}}`` on success.
        """
        if order_type is None:
            order_type = {"limit": {"tif": "Gtc"}}
        nonce = nonce if nonce is not None else int(time.time() * 1000)

        # Build the single-order action. Keys MUST be alphabetical because
        # the Hyperliquid SDK's msgpack encoding is order-sensitive and
        # our enclave's `msgpack_action` defaults to alphabetical (see
        # signer.rs comment for the full reasoning).
        order_obj: dict[str, Any] = {
            "a": asset_index,
            "b": is_buy,
            "p": price,
            "r": reduce_only,
            "s": size,
            "t": order_type,
        }
        if cloid is not None:
            order_obj["c"] = cloid

        action: dict[str, Any] = {
            "grouping": grouping,
            "orders": [order_obj],
            "type": "order",
        }

        return self._sign_and_post(
            kind="order",
            action=action,
            nonce=nonce,
            vault_address=vault_address,
        )

    def cancel(
        self,
        *,
        asset_index: int,
        oid: int,
        vault_address: str | None = None,
        nonce: int | None = None,
    ) -> httpx.Response:
        """Cancel a single open order.

        Args:
            asset_index: Same as in ``order(...)``.
            oid: Hyperliquid-issued order id (an integer; the API
                returns it under ``response.data.statuses[i].resting.oid``
                when an order rests).
            vault_address: Optional vault address.
            nonce: Override nonce; defaults to current Unix ms.

        Returns:
            ``httpx.Response`` from ``POST /exchange``.
        """
        nonce = nonce if nonce is not None else int(time.time() * 1000)
        action: dict[str, Any] = {
            "cancels": [{"a": asset_index, "o": oid}],
            "type": "cancel",
        }
        return self._sign_and_post(
            kind="cancel",
            action=action,
            nonce=nonce,
            vault_address=vault_address,
        )

    def _sign_and_post(
        self,
        *,
        kind: str,
        action: dict[str, Any],
        nonce: int,
        vault_address: str | None,
    ) -> httpx.Response:
        """Shared helper: request signature from gateway, then POST to
        Hyperliquid's ``/exchange``."""
        sign_result = self._signer.sign_eip712(
            exchange=self.exchange_name,
            kind=kind,
            action=action,
            nonce=nonce,
            vault_address=vault_address,
        )
        # `sign_result` is the `signature` object as returned by the
        # gateway. Submit per Hyperliquid spec.
        body: dict[str, Any] = {
            "action": action,
            "nonce": nonce,
            "signature": sign_result,
            "vaultAddress": vault_address,
        }
        url = f"{self.base_url}/exchange"
        return self._exchange_client.post(
            url,
            headers={"Content-Type": "application/json"},
            json=body,
        )
