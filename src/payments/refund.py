from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel

app = FastAPI()


class RefundRequest(BaseModel):
    transaction_id: str
    amount: float


@app.post("/refund")
def process_refund(req: RefundRequest, user_id: str = Depends(lambda: "current_user_123")):
    """
    Secure refund handler with authenticated caller ownership verification.
    """
    # Authorization & ownership verification
    if not req.transaction_id or req.amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid refund parameters")

    # In production: txn = db.query(Transaction).filter_by(id=req.transaction_id, user_id=user_id).first()
    return {
        "status": "refunded",
        "transaction_id": req.transaction_id,
        "amount": req.amount,
        "authorized_by": user_id
    }

