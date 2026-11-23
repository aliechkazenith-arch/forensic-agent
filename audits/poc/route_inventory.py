from backend.app.main import create_app
import inspect
from fastapi.routing import APIRoute

app = create_app()

def unwrap_routes(router, prefix=""):
    routes = []
    current_prefix = prefix + getattr(router, "prefix", "")
    for r in getattr(router, "routes", []):
        if hasattr(r, "original_router"):
            routes.extend(unwrap_routes(r.original_router, current_prefix))
        elif isinstance(r, APIRoute):
            routes.append((current_prefix + r.path, r))
        elif hasattr(r, "routes"):
            routes.extend(unwrap_routes(r, current_prefix))
    return routes

leaf_routes = unwrap_routes(app.router)
print(f"Total endpoints found: {len(leaf_routes)}")

inventory = []
for full_path, route in leaf_routes:
    endpoint = route.endpoint
    sig = inspect.signature(endpoint) if endpoint else None
    
    # Check dependencies on route and endpoint
    all_deps = list(route.dependencies)
    auth_type = "None (Public)"
    role_req = "None"
    
    # Check default arguments in endpoint signature
    accepts_files = False
    accepts_paths = False
    accepts_text = False
    
    if sig:
        for p_name, param in sig.parameters.items():
            ann = str(param.annotation)
            def_str = str(param.default)
            if "get_current_user" in def_str or "get_current_user" in ann:
                auth_type = "JWT Bearer (get_current_user)"
            if "require_roles" in def_str:
                role_req = def_str
            if "UploadFile" in ann or "File" in def_str:
                accepts_files = True
            if "evidence_path" in p_name or "file_path" in p_name or "path" in p_name:
                accepts_paths = True
            if "str" in ann or "prompt" in p_name or "query" in p_name:
                accepts_text = True
                
    for d in all_deps:
        call_str = str(getattr(d, "dependency", d))
        if "get_current_user" in call_str:
            auth_type = "JWT Bearer"
        if "require_roles" in call_str:
            role_req = call_str

    methods_str = ",".join(sorted(route.methods - {"HEAD", "OPTIONS"})) or ",".join(sorted(route.methods))
    
    inventory.append({
        "methods": methods_str,
        "path": route.path,
        "endpoint": route.name,
        "auth": auth_type,
        "role": role_req,
        "accepts_files": accepts_files,
        "accepts_paths": accepts_paths,
        "accepts_text": accepts_text,
        "summary": (route.summary or route.description or (endpoint.__doc__ or "").strip().split("\n")[0])
    })

inventory.sort(key=lambda x: (x["path"], x["methods"]))

print("| Method | Path | Endpoint | Auth | Role Req | Accepts | Summary |")
print("|---|---|---|---|---|---|---|")
for item in inventory:
    accepts = []
    if item["accepts_files"]: accepts.append("Files")
    if item["accepts_paths"]: accepts.append("Paths")
    if item["accepts_text"]: accepts.append("Text")
    acc_str = ", ".join(accepts) or "JSON/Query"
    print(f"| `{item['methods']}` | `{item['path']}` | `{item['endpoint']}` | {item['auth']} | {item['role']} | {acc_str} | {item['summary']} |")
