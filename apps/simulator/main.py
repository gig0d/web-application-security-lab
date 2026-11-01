from fastapi import FastAPI

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/public/handbook")
def handbook() -> dict[str, str]:
    return {"document": "Fictional support handbook. Customers may preview this document."}


@app.get("/private/metadata")
def metadata() -> dict[str, str]:
    return {"classification": "internal-simulation", "value": "SYNTHETIC-METADATA-ONLY"}
