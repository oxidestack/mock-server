"""Kind `crud` (B4): `CrudDataStore`, `CrudActionHandler` and `CrudDispatcher`, one case per test method,
replayed through `PUT /mockserver/crud` and the CRUD requests the dispatcher routes."""
import json
import re
import urllib.parse

from harvest import Kind, control, request_steps, reset

DEFAULT_MAX_ITEMS = 10000
# a store a test uses without a handler is served here
STORE_PATH = "/harvested"
# the dispatcher's routing (CrudDispatcher.dispatch): handler method -> (HTTP method, by id)
ROUTES = {"handleList": ("GET", False), "handleCreate": ("POST", False), "handleGetById": ("GET", True),
          "handleUpdate": ("PUT", True), "handlePatch": ("PATCH", True), "handleDelete": ("DELETE", True)}
STORE_ROUTES = {"getAll": ("GET", False), "size": ("GET", False), "create": ("POST", False), "getById": ("GET", True),
                "update": ("PUT", True), "patch": ("PATCH", True), "delete": ("DELETE", True)}


def group_crud(lines):
    """The recorded calls of one test method, in order, as one case."""
    cases = []
    for call in lines:
        if cases and cases[-1]["test"] == call["test"]:
            cases[-1]["calls"].append(call)
        else:
            cases.append({"boundary": "CrudActionHandler", "test": call["test"], "calls": [call]})
    return cases


def absolute(path):
    return path if not isinstance(path, str) or path.startswith("/") else "/" + path


def routes_to(path, base, by_id):
    """Whether the dispatcher sends `path` (no query) to a handler at `base` for a collection or a by-id call."""
    normalized = path[:-1] if path.endswith("/") else path
    if not by_id:
        return normalized == base
    return normalized.startswith(base + "/") and "/" not in normalized[len(base) + 1:] and len(normalized) > len(base) + 1


class Case:
    def __init__(self, calls):
        self.calls = calls
        self.stores = {c["store"]: c for c in calls if c["call"] == "newStore"}
        self.handlers = {c["handler"]: c for c in calls if c["call"] == "newHandler"}
        # a store's base path: its first handler's, else STORE_PATH
        self.base = {}
        for h in self.handlers.values():
            self.base.setdefault(h["store"], h["basePath"])
        self.steps = []
        self.registered = {}  # base path -> store currently registered there
        self.used = set()  # stores whose wire state a later re-registration would lose
        self.ids = {}  # an id a create generated in the JVM -> its capture key
        self.pending_capture = None

    def store_base(self, store):
        return self.base.get(store, STORE_PATH)

    def register(self, store, base, note, requested=None, rejected=False):
        """`PUT /mockserver/crud` for `store` at `base` (the body's `basePath` is `requested` when the call named its
        own), unless it is already the store there; None, else why it has no wire form."""
        current = self.registered.get(base)
        if current == store and requested is None:
            return None
        if current is not None and current in self.used:
            return "two stores at one base path, both used (the wire keeps one per path)"
        if store not in self.stores:
            return "store built outside the recorded calls"
        definition = self.stores[store]
        if definition.get("maxItems") != DEFAULT_MAX_ITEMS:
            return "store item cap (maxItems) has no wire form"
        body = {"basePath": base if requested is None else requested, "idField": definition["idField"],
                "idStrategy": definition["idStrategy"], "initialData": definition["items"]}
        self.steps.append(control("/mockserver/crud", body, note))
        if not rejected:
            self.registered[base] = store
        return None

    def substitute(self, text):
        for generated, key in self.ids.items():
            text = text.replace(generated, "{{capture:" + key + "}}")
        return text

    def captures(self, step, created, id_field):
        """A UUID a create generated, kept from the answer for the calls that name it later."""
        if not isinstance(created, dict):
            return
        value = created.get(id_field)
        if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value):
            key = "id" + str(len(self.ids) + 1)
            self.ids[value] = key
            step.setdefault("capture", []).append({"bodyRegex": '"' + re.escape(id_field) + '"\\s*:\\s*"([^"]+)"', "as": key})

    def wire(self, method, path, query, body, note):
        step = {"method": method, "path": self.substitute(path) + (("?" + query) if query else "")}
        if body is not None:
            step["body"] = self.substitute(body)
        step["note"] = note
        self.steps.append(step)
        return step


def id_path(base, id_value):
    if not isinstance(id_value, str) or "/" in id_value or id_value == "":
        return None
    return base + "/" + urllib.parse.quote(id_value, safe="-._~:@!$&'()*+,;=")


def convert_crud(case):
    """Each store a call reaches is registered at its handler's base path (`PUT /mockserver/crud` with the items it was
    built with) before its first use; a handler's `handle*(request)` is the request the dispatcher routes to that
    method, a store method called directly the CRUD request that makes the handler call it (`size` and `getAll` a
    list, `clear` a re-registration without items), a dispatcher's `dispatch(request)` the request itself,
    `register` the handler's store registered at that path, `reset()` `PUT /mockserver/reset`."""
    calls = case["calls"]
    for call in calls:
        if "unserialisable" in call:
            return None, "unserialisable: " + call["unserialisable"]
    c = Case(calls)
    for call in calls:
        kind = call["call"]
        if kind in ("newStore", "newHandler"):
            continue
        if kind == "store":
            store, method, args = call["store"], call["method"], call["args"]
            base = c.store_base(store)
            reason = c.register(store, base, "CrudDataStore (" + method + ")")
            if reason:
                return None, reason
            c.used.add(store)
            if method == "clear":
                definition = c.stores[store]
                c.steps.append(control("/mockserver/crud", {"basePath": base, "idField": definition["idField"],
                                                            "idStrategy": definition["idStrategy"], "initialData": []},
                                       "CrudDataStore.clear"))
                continue
            http_method, by_id = STORE_ROUTES[method]
            path = base
            if by_id:
                path = id_path(base, args[0])
                if path is None:
                    return None, "id not a path segment"
            body = None
            if method in ("create", "update", "patch"):
                item = args[-1]
                if not isinstance(item, dict):
                    return None, "item not a JSON object"
                body = json.dumps(item)
            step = c.wire(http_method, path, None, body, "CrudDataStore." + method)
            if method == "create":
                c.captures(step, call.get("result"), c.stores[store]["idField"])
        elif kind == "handle":
            handler = c.handlers.get(call["handler"])
            if handler is None:
                return None, "handler built outside the recorded calls"
            store, base = handler["store"], handler["basePath"]
            reason = c.register(store, base, "CrudActionHandler")
            if reason:
                return None, reason
            c.used.add(store)
            request = json.loads(call["request"])
            path = absolute(request.get("path", "/"))
            http_method, by_id = ROUTES[call["method"]]
            if not routes_to(path, base, by_id):
                return None, call["method"] + " with a path the dispatcher routes elsewhere"
            request["path"], request["method"] = path, http_method
            step, reason = request_steps(request)
            if step is None:
                return None, reason
            step["path"] = c.substitute(step["path"])
            if isinstance(step.get("body"), str):
                step["body"] = c.substitute(step["body"])
            step["note"] = "CrudActionHandler." + call["method"]
            c.steps.append(step)
            if call["method"] == "handleCreate" and call.get("response"):
                response = json.loads(call["response"])
                try:
                    created = json.loads(response.get("body") if isinstance(response.get("body"), str) else json.dumps((response.get("body") or {}).get("json")))
                except (TypeError, ValueError):
                    created = None
                c.captures(step, created, c.stores[store]["idField"])
        elif kind == "dispatcher":
            method = call["method"]
            if method == "register":
                handler = c.handlers.get(call["handler"])
                if handler is None:
                    return None, "handler built outside the recorded calls"
                reason = c.register(handler["store"], handler["basePath"], "CrudDispatcher.register", requested=call["basePath"],
                                    rejected="thrown" in call)
                if reason:
                    return None, reason
            elif method == "reset":
                c.steps.append(dict(reset(), note="CrudDispatcher.reset"))
                c.registered.clear()
            elif method == "unregister":
                return None, "CrudDispatcher.unregister has no wire form"
            else:
                request = json.loads(call["request"])
                request["path"] = absolute(request.get("path", "/"))
                step, reason = request_steps(request)
                if step is None:
                    return None, reason
                step["path"] = c.substitute(step["path"])
                if isinstance(step.get("body"), str):
                    step["body"] = c.substitute(step["body"])
                step["note"] = "CrudDispatcher.dispatch"
                c.steps.append(step)
                for (b, store) in c.registered.items():
                    c.used.add(store)
                if call.get("response") and request.get("method") == "POST":
                    response = json.loads(call["response"])
                    body = response.get("body")
                    try:
                        created = json.loads(body if isinstance(body, str) else json.dumps((body or {}).get("json")))
                    except (TypeError, ValueError):
                        created = None
                    for b, store in c.registered.items():
                        if routes_to(request["path"].split("?")[0], b, False):
                            c.captures(step, created, c.stores[store]["idField"])
        else:
            return None, "unknown call " + kind
    if not c.steps:
        return None, "constructors only (the package-private extractIdFromPath, the normalised base path)"
    return c.steps, None


KINDS = [Kind("crud", "B4", convert_crud, group=group_crud, per_test=True)]
