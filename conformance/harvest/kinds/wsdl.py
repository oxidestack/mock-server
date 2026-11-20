"""Kind `wsdl` (B4): `WsdlExpectationGenerator.generate(wsdl)`."""
from harvest import Kind, RETRIEVE_ACTIVE, control


def convert_wsdl(case):
    """The WSDL sent to `PUT /mockserver/wsdl` (201 with the generated expectations, or 400 with the generator's
    error), then the active expectations, which show what was added."""
    if case.get("wsdl") is None:
        return None, "null WSDL (a request without a body is a different input)"
    put = control("/mockserver/wsdl", case["wsdl"], "WsdlExpectationGenerator.generate")
    put["headers"] = {"Content-Type": "text/xml"}
    return [put, control(RETRIEVE_ACTIVE, "", "active expectations")], None


KINDS = [Kind("wsdl", "B4", convert_wsdl)]
