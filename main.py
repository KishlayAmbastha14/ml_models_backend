from fastapi import FastAPI
from pydantic import BaseModel,Field,computed_field
from fastapi.responses import JSONResponse
from typing import List,Literal,Annotated
import pandas as pd
import joblib
from fastapi import Query



import __main__
from preprocess import DropAndClip
__main__.DropAndClip = DropAndClip




dt = joblib.load("decision_tree.joblib")
rf = joblib.load("pipeline_rf_tree.joblib")

knn = joblib.load("pipeline_knn.joblib")
lr = joblib.load("pipeline_lr.joblib")

ada = joblib.load("pipeline_ada.joblib")
cat = joblib.load("pipeline_cat.joblib")

svc = joblib.load("pipeline_svm.joblib")
xgb = joblib.load("xgb_.joblib")

gb = joblib.load("pipeline_gb1.joblib")


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


model_registry = {
   "lr" : lr,
   "knn" : knn,
   "dt" : dt,
   "rf" : rf,
   "svc" : svc,
   "cat" : cat,
   "xgb" : xgb,
   "ada" : ada,
   "gb" : gb
}

@app.post("/predict")
async def predict_intrusion(data:IntrusionRequest,
                            model:Literal["lr","knn","dt","rf","svc","cat","xgb","ada","gb"] = 
                            Query(
                               default="xgb",
                               description="select ml model for predictions"
                            )):
    
    df = pd.DataFrame([data.model_dump()])
    selected_model = model_registry.get(model.lower())


    if selected_model is None:
        return JSONResponse(
            status_code=400,
            content={"error": "Invalid model choice"}
        )
    if(selected_model == 'svc'):
        prediction = int(selected_model.predict(df)[0])
        probability = float(xgb.predict_proba(df).max())
    else:
        prediction = int(selected_model.predict(df)[0])
        probability = float(xgb.predict_proba(df).max())


    return {
        "model_used": model,
        "prediction": prediction,
        "confidence": round(probability, 4)
    }


# prediction = int(svc.predict(data)[0])
# #     probability = float(xgb.predict_proba(data).max())

# #     return JSONResponse(
# #         status_code=200,content={
# #             "prediction":prediction,
# #             "confidence_matrix":round(float(probability),4)
# #         }
# #     )

# @app.post("/decision_tree_predict")
# async def decision_tree_model(data:IntrusionRequest):
#     data = pd.DataFrame([data.model_dump()])
#     prediction = int(dt.predict(data)[0])
#     probability = float(dt.predict_proba(data).max())

#     return JSONResponse(
#         status_code=200,
#         content={
#             "prediction":prediction,
#             "confidence":round(float(probability),4)
#          }
#     )

# @app.post("/randomforest")
# async def random_forest(data:IntrusionRequest):
#     data = pd.DataFrame([data.model_dump()])
#     prediction = int(rf.predict(data)[0])
#     probability = float(rf.predict_proba(data).max())

#     return JSONResponse(
#         status_code=200,content = {
#             "prediction": prediction,
#             "confidence_meter":round(float(probability),4)
#         }
#     )



# @app.post("/lregression")
# async def lr_regression(data:IntrusionRequest):
#     data = pd.DataFrame([data.model_dump()])
#     prediction = int(lr.predict(data)[0])
#     probability = float(lr.predict_proba(data).max())

#     return JSONResponse(
#         status_code=200,content = {
#             "prediction": prediction,
#             "confidence_meter":round(float(probability),4)
#         }
#     )


# @app.post("/knnneigbour")
# async def knn_neighbour(data:IntrusionRequest):
#     data = pd.DataFrame([data.model_dump()])
#     prediction = int(knn.predict(data)[0])
#     probability = float(knn.predict_proba(data).max())

#     return JSONResponse(
#         status_code=200,content = {
#             "prediction": prediction,
#             "confidence_meter":round(float(probability),4)
#         }
#     )


# @app.post("/catboost")
# async def cat_boost(data:IntrusionRequest):
#     data = pd.DataFrame([data.model_dump()])
#     prediction = int(cat.predict(data)[0])
#     probability = float(cat.predict_proba(data).max())

#     return JSONResponse(
#         status_code=200,content = {
#             "prediction": prediction,
#             "confidence_meter":round(float(probability),4)
#         }
#     )

# @app.post("/xgbboost")
# async def xgb_boost(data:IntrusionRequest):
#     data = pd.DataFrame([data.model_dump()])
#     prediction = int(xgb.predict(data)[0])
#     probability = float(xgb.predict_proba(data).max())

#     return JSONResponse(
#         status_code=200,content = {
#             "prediction": prediction,
#             "confidence_meter":round(float(probability),4)
#         }
#     )

# @app.post("/support_vector_classifier")
# async def support_vector_classifier(data:IntrusionRequest):
#     data = pd.DataFrame([data.model_dump()])
#     prediction = int(svc.predict(data)[0])
#     probability = float(xgb.predict_proba(data).max())

#     return JSONResponse(
#         status_code=200,content={
#             "prediction":prediction,
#             "confidence_matrix":round(float(probability),4)
#         }
#     )
