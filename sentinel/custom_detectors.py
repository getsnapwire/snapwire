"""
Custom protocol detectors for the Snapwire Sentinel Proxy.

This file is auto-loaded by the Sentinel Proxy at startup. Any function
decorated with @register_protocol will be automatically registered and
used for tool-call detection alongside the built-in detectors.

This file survives upstream updates — your custom detectors won't be
overwritten when you pull new versions of Snapwire.

HOW TO ADD A DETECTOR:
    1. Import register_protocol and DetectedToolCall (already done below)
    2. Write a function that takes a dict (the JSON body) and returns
       a list of DetectedToolCall namedtuples
    3. Decorate it with @register_protocol
    4. Restart the Sentinel Proxy

EXAMPLE:
    @register_protocol
    def detect_my_provider(body: dict) -> list:
        results = []
        tool_calls = body.get("my_tool_calls")
        if isinstance(tool_calls, list):
            for tc in tool_calls:
                if isinstance(tc, dict) and "name" in tc:
                    results.append(DetectedToolCall(
                        tool_name=tc["name"],
                        parameters=tc.get("args", {}),
                        protocol="my_provider",
                        confidence=0.9
                    ))
        return results
"""

from sentinel.detector import register_protocol, DetectedToolCall  # noqa: F401
