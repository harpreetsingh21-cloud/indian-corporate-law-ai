import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from bson import ObjectId
from fastapi import APIRouter, Header, HTTPException, status

from shared.database.mongo import DatabaseManager
from shared.security.jwt import extract_user_from_token

router = APIRouter(prefix="/api/auth/payment", tags=["payment"])

_token = {"value": None, "expires_at": 0}


def _base_url() -> str:
    return os.getenv("PHONEPE_BASE_URL", "https://api-preprod.phonepe.com/apis/pg-sandbox").rstrip("/")


def _user_id(authorization: Optional[str]) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    return extract_user_from_token(authorization.removeprefix("Bearer "))


async def _access_token() -> str:
    if _token["value"] and _token["expires_at"] - 60 > time.time():
        return _token["value"]
    client_id = os.getenv("PHONEPE_CLIENT_ID")
    client_secret = os.getenv("PHONEPE_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Payments are not configured")
    async with httpx.AsyncClient(timeout=20) as client:
        res = await client.post(
            f"{_base_url()}/v1/oauth/token",
            data={
                "client_id": client_id,
                "client_version": os.getenv("PHONEPE_CLIENT_VERSION", "1"),
                "client_secret": client_secret,
                "grant_type": "client_credentials",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    if res.status_code != 200:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"PhonePe login failed: {res.text[:200]}")
    data = res.json()
    _token["value"] = data["access_token"]
    _token["expires_at"] = data.get("expires_at") or time.time() + 600
    return _token["value"]


@router.post("/create-order")
async def create_order(authorization: Optional[str] = Header(None)):
    user_id = _user_id(authorization)
    price = int(os.getenv("PRO_PRICE_INR", "299"))
    merchant_order_id = f"LB{uuid.uuid4().hex[:24]}"
    frontend = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
    token = await _access_token()

    body = {
        "merchantOrderId": merchant_order_id,
        "amount": price * 100,
        "expireAfter": 1200,
        "metaInfo": {"udf1": user_id, "udf2": "pro_monthly"},
        "paymentFlow": {
            "type": "PG_CHECKOUT",
            "message": "LegalBuddy Pro plan",
            "merchantUrls": {"redirectUrl": f"{frontend}/payment-done?order_id={merchant_order_id}"},
        },
    }
    async with httpx.AsyncClient(timeout=20) as client:
        res = await client.post(
            f"{_base_url()}/checkout/v2/pay",
            json=body,
            headers={"Authorization": f"O-Bearer {token}", "Content-Type": "application/json"},
        )
    if res.status_code != 200:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"PhonePe order failed: {res.text[:200]}")
    data = res.json()

    db = DatabaseManager.get_db()
    await db.payments.insert_one({
        "gateway": "phonepe",
        "user_id": ObjectId(user_id),
        "order_id": merchant_order_id,
        "phonepe_order_id": data.get("orderId"),
        "amount": price,
        "currency": "INR",
        "status": "created",
        "created_at": datetime.now(timezone.utc),
    })
    return {"order_id": merchant_order_id, "redirect_url": data.get("redirectUrl")}


@router.get("/status/{order_id}")
async def payment_status(order_id: str, authorization: Optional[str] = Header(None)):
    user_id = _user_id(authorization)
    db = DatabaseManager.get_db()

    payment = await db.payments.find_one({"order_id": order_id, "user_id": ObjectId(user_id)})
    if not payment:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Order not found")
    if payment["status"] == "paid":
        return {"state": "COMPLETED", "expires": payment.get("expires")}
    if payment["status"] == "failed":
        return {"state": "FAILED"}

    token = await _access_token()
    headers = {"Authorization": f"O-Bearer {token}", "Content-Type": "application/json"}
    merchant_id = os.getenv("PHONEPE_MERCHANT_ID")
    if merchant_id:
        headers["X-MERCHANT-ID"] = merchant_id
    async with httpx.AsyncClient(timeout=20) as client:
        res = await client.get(f"{_base_url()}/checkout/v2/order/{order_id}/status", headers=headers)
    if res.status_code != 200:
        return {"state": "PENDING"}
    data = res.json()
    state = data.get("state", "PENDING")

    if state == "FAILED":
        await db.payments.update_one({"_id": payment["_id"]}, {"$set": {"status": "failed"}})
        return {"state": "FAILED"}
    if state != "COMPLETED":
        return {"state": "PENDING"}
    if int(data.get("amount", 0)) != payment["amount"] * 100:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Amount mismatch")

    now = datetime.now(timezone.utc)
    user = await db.users.find_one({"_id": ObjectId(user_id)}, {"subscription_expiry": 1})
    current = user.get("subscription_expiry") if user else None
    if current and current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    start = current if current and current > now else now
    expiry = start + timedelta(days=30)

    claimed = await db.payments.update_one(
        {"_id": payment["_id"], "status": {"$ne": "paid"}},
        {"$set": {"status": "paid", "paid_at": now, "expires": expiry.isoformat()}},
    )
    if claimed.modified_count == 1:
        await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"subscription_tier": "pro", "subscription_expiry": expiry, "unlimited": True}},
        )
    return {"state": "COMPLETED", "expires": expiry.isoformat()}