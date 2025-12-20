from fastapi import FastAPI
from pydantic import BaseModel,Field,computed_field
from fastapi.responses import JSONResponse
from typing import List,Literal,Annotated
import pandas as pd
import joblib



import __main__
from preprocess import DropAndClip
__main__.DropAndClip = DropAndClip


# with open('dt_.joblib','rb') as f:
#     model = joblib.load(f)

# with open('decision_tree.joblib','rb') as f:
#     model = joblib.load(f)

decision_tree = joblib.load("decision_tree.joblib")

app = FastAPI(title="Web Intrusion Detection API")


   
class IntrusionRequest(BaseModel):
    # =====================
    # BASIC CONNECTION INFO
    # =====================
    duration: int = Field(
        ...,
        ge=0,
        le=60000,
        description="Length of the connection in seconds",
        example=120
    )

    # protocol_type: Literal["tcp", "udp", "icmp"] = Field(
    #     ...,
    #     description="Transport layer protocol used"
    # )

    protocol_type : int = Field(
        ..., 
        ge=0,
        le=2,
        description="Protocol type (0=tcp, 1=udp, 2=icmp)",
        example=0
    )


    service : int = Field(
        ...,
        ge=0,
        le=69,
        description="Encoded network service between (0–69)",
        example=34
    )

    flag: int = Field(
        ...,
        ge=0,
        le=10,
        description="Encoded connection status flag (0–10)",
        example=1
    )

    # src_bytes: int = Field(..., ge=0)
    # dst_bytes: int = Field(..., ge=0)
    src_bytes: int = Field(
        ...,
        ge=0,
        description="Bytes sent from source to destination",
        example=181
    )

    dst_bytes: int = Field(
        ...,
        ge=0,
        description="Bytes sent from destination to source",
        example=5450
    )

    # =======================
    # CONTENT FEATURES
    # =======================
    land: int = Field(
        ...,
        ge=0,
        le=1,
        description="1 if connection is from/to the same host/port, else 0"
    )

    logged_in: int = Field(
        ...,
        ge=0,
        le=1,
        description="1 if successfully logged in, else 0"
    )

    root_shell: int = Field(
        ...,
        ge=0,
        le=1,
        description="1 if root shell obtained, else 0"
    )

    is_guest_login: int = Field(
        ...,
        ge=0,
        le=1,
        description="1 if guest login, else 0"
    )

    # land: int = Field(..., ge=0, le=1)
    wrong_fragment: int = Field(..., ge=0)
    urgent: int = Field(..., ge=0)
    hot: int = Field(..., ge=0)
    num_failed_logins: int = Field(..., ge=0)

    # logged_in: int = Field(..., ge=0, le=1)
    # root_shell: int = Field(..., ge=0, le=1)
    su_attempted: int = Field(..., ge=0, le=1)
    num_file_creations: int = Field(..., ge=0)
    num_outbound_cmds: int = Field(..., ge=0)

    is_host_login: int = Field(..., ge=0, le=1)
    # is_guest_login: int = Field(..., ge=0, le=1)

    # =======================
    # TRAFFIC FEATURES
    # =======================
    count: int = Field(..., ge=0)
    srv_count: int = Field(..., ge=0)

    serror_rate: float = Field(..., ge=0.0, le=1.0)
    srv_serror_rate: float = Field(..., ge=0.0, le=1.0)
    rerror_rate: float = Field(..., ge=0.0, le=1.0)
    srv_rerror_rate: float = Field(..., ge=0.0, le=1.0)

    same_srv_rate: float = Field(..., ge=0.0, le=1.0)
    diff_srv_rate: float = Field(..., ge=0.0, le=1.0)
    srv_diff_host_rate: float = Field(..., ge=0.0, le=1.0)

    # =======================
    # HOST BASED FEATURES
    # =======================
    dst_host_count: int = Field(..., ge=0)
    dst_host_srv_count: int = Field(..., ge=0)

    dst_host_same_srv_rate: float = Field(..., ge=0.0, le=1.0)
    dst_host_diff_srv_rate: float = Field(..., ge=0.0, le=1.0)
    dst_host_same_src_port_rate: float = Field(..., ge=0.0, le=1.0)
    dst_host_srv_diff_host_rate: float = Field(..., ge=0.0, le=1.0)

    dst_host_serror_rate: float = Field(..., ge=0.0, le=1.0)
    dst_host_srv_serror_rate: float = Field(..., ge=0.0, le=1.0)
    dst_host_rerror_rate: float = Field(..., ge=0.0, le=1.0)
    dst_host_srv_rerror_rate: float = Field(..., ge=0.0, le=1.0)

    class Config:
        schema_extra = {
            "example": {
                "duration": 120,
                "protocol_type": "tcp",
                "service": "http",
                "flag": "SF",
                "src_bytes": 181,
                "dst_bytes": 5450,
                "land": 0,
                "logged_in": 1,
                "root_shell": 0,
                "is_guest_login": 0,
                "count": 5,
                "srv_count": 3,
                "dst_host_count": 50,
                "dst_host_srv_count": 25,
                "serror_rate": 0.0,
                "srv_serror_rate": 0.0,
                "rerror_rate": 0.0,
                "srv_rerror_rate": 0.0,
                "same_srv_rate": 0.8,
                "diff_srv_rate": 0.2,
                "srv_diff_host_rate": 0.1
            }
        }

  

@app.get("/")
async def main():
  return {"hello to fastapi backend"}

@app.post("/decision_tree_predict")
async def decision_tree_model(data:IntrusionRequest):
    data = pd.DataFrame([data.model_dump()])
    prediction = int(decision_tree.predict(data)[0])
    probability = float(decision_tree.predict_proba(data).max())

    return JSONResponse(
        status_code=200,
        content={
            "prediction":prediction,
            "confidence":round(float(probability),4)
         }
    )
