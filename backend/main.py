import os
import uuid
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
import requests

from models import (
    FlowRequest,
    ThreatResponse,
    Threat,
    DreadRequest,
    DreadResponse
)

from stride_agent import analyze_system_flow

app = FastAPI()

# CORS (allow frontend to access backend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # allow all origins for MVP
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {"status": "Backend running"}


# ---------------- STRIDE ANALYSIS ----------------
@app.post("/analyze", response_model=ThreatResponse)
def analyze_flow(flow_request: FlowRequest):
    threats = analyze_system_flow(flow_request.flow)
    return {"threats": threats}


# ---------------- DREAD SCORING ----------------
@app.post("/dread", response_model=DreadResponse)
def calculate_overall_dread(dread: DreadRequest):
    values = [
        dread.damage,
        dread.reproducibility,
        dread.exploitability,
        dread.affected_users,
        dread.discoverability
    ]
    if any(v is None for v in values):
        raise HTTPException(status_code=400, detail="All five DREAD values must be provided.")
    if any((not isinstance(v, (int, float)) or v < 0 or v > 10) for v in values):
        raise HTTPException(status_code=400, detail="DREAD values must be numbers between 0 and 10.")

    score = round(sum(values) / 5.0, 2)
    return {"score": score}


# ---------------- DFD GENERATION (using Kroki API + local save) ----------------
@app.post("/generate_dfd")
async def generate_dfd(request: Request):
    """
    Accepts JSON with 'nodes' and 'flows', generates a DFD PNG using the Kroki.io Graphviz API,
    saves it locally in ./dfds/, and returns the PNG.
    """
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    nodes = data.get("nodes", [])
    flows = data.get("flows", [])

    if not isinstance(nodes, list) or not isinstance(flows, list) or len(nodes) == 0 or len(flows) == 0:
        raise HTTPException(status_code=400, detail="Request JSON must include non-empty 'nodes' and 'flows' arrays.")

    # Build DOT graph
    dot = "digraph DFD {\n"
    dot += "  graph [splines=true, overlap=false];\n"
    dot += "  node [shape=box, style=rounded, color=gray40, fontname=Helvetica];\n"
    dot += "  edge [color=gray30, fontname=Helvetica];\n\n"

    for node in nodes:
        node_id = node.get("id")
        label = node.get("label", node_id)
        if not node_id:
            raise HTTPException(status_code=400, detail="Each node must have an 'id' field.")
        dot += f'  "{node_id}" [label="{label}"];\n'

    for flow in flows:
        src = flow.get("source")
        tgt = flow.get("target")
        if not src or not tgt:
            raise HTTPException(status_code=400, detail="Each flow must include 'source' and 'target' fields.")
        label = flow.get("label", "")
        stride = flow.get("stride", [])
        if isinstance(stride, list) and len(stride) > 0:
            label += "\\n[" + ", ".join(stride) + "]"
        dot += f'  "{src}" -> "{tgt}" [label="{label}"];\n'

    dot += "}\n"

    # Send DOT to Kroki.io for rendering
    try:
        response = requests.post(
            "https://kroki.io/graphviz/png",
            data=dot.encode("utf-8"),
            headers={"Content-Type": "text/plain"},
            timeout=20
        )
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error connecting to Kroki.io: {str(e)}")

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail=f"Kroki rendering failed: {response.status_code}")

    # Ensure dfds folder exists
    DFD_FOLDER = os.path.join(os.getcwd(), "dfds")
    os.makedirs(DFD_FOLDER, exist_ok=True)

    # Save PNG locally
    file_id = f"dfd_{uuid.uuid4().hex}.png"
    file_path = os.path.join(DFD_FOLDER, file_id)
    with open(file_path, "wb") as f:
        f.write(response.content)

    print(f"✅ DFD saved locally at: {file_path}")

    # Return the PNG to frontend
    return Response(content=response.content, media_type="image/png")
