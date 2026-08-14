# spear-guard
#
# Python SDK for the [Spear](https://github.com/sunnypatneedi/spear) HTTP API.
# Gates stay in TypeScript; this package is a thin client.

```bash
pip install spear-guard
docker run -p 7700:7700 -e SPEAR_MODE=enforce sunnypatneedi/spear-api
```

```python
from spear_guard import quick, SpearBlockedError

spear = quick("balanced", mode="enforce", url="http://localhost:7700")
pre = spear.pre([{"role": "user", "content": "Hello"}])
if not pre.allowed:
    raise SpearBlockedError(pre.reason)

with spear.session("agent-001") as session:
    step = session.step([{"role": "user", "content": "Hello"}])
```

Async:

```python
from spear_guard import AsyncSpear

spear = AsyncSpear("http://localhost:7700")
async with await spear.session("agent-001") as session:
    step = await session.step([{"role": "user", "content": "Hello"}])
```

LangChain:

```python
from spear_guard.integrations.langchain import SpearCallbackHandler

llm = ChatOpenAI(
    callbacks=[SpearCallbackHandler(spear_url="http://localhost:7700", mode="enforce")]
)
```
