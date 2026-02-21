# Questions for VP of Engineering Meeting (Security Startup, Series B)

## Validating the Problem

1. **How is your team handling security around LLM integrations today — prompt injection, data exfiltration, tool misuse? Is it homegrown or are you using something off the shelf?**
   - Goal: Learn if they've felt the pain, and map the competitive landscape from a buyer's perspective.

2. **When your engineers build agentic features (tool-calling, RAG), who owns the security review? Is it the feature team, a platform team, or AppSec?**
   - Goal: Identify who your buyer/champion is inside an org.

3. **Have you had any near-misses or incidents related to LLM outputs leaking internal data, system prompts, or PII?**
   - Goal: Validate urgency. If they have war stories, Spear's canary tokens and output gate are directly relevant.

## Understanding Buyer Behavior

4. **At Series B, when you evaluate a new security dependency, what matters more — that it's a library you embed, a sidecar/API you call, or an agent-native integration (MCP, hooks)?**
   - Goal: Informs roadmap prioritization (npm library vs. Docker HTTP API vs. MCP server).

5. **How much does your team care about shadow/observe mode before enforcing a new security control? Or do you just want hard blocks?**
   - Goal: Validate whether the `shadow → enforce` deployment model is a real differentiator or nice-to-have.

6. **Would policy-as-code in YAML that's reviewable in PRs and testable in CI resonate with your eng team, or does security tooling need to be more invisible?**
   - Goal: Test whether the policy architecture is a selling point or friction.

## Positioning & Go-to-Market

7. **When you think about compliance (SOC 2, EU AI Act), is demonstrating LLM-specific controls something auditors are already asking for, or is it still ahead of the curve?**
   - Goal: Determine whether compliance is a near-term or long-term GTM lever.

8. **If a tool like this existed, would your team adopt it bottom-up (engineer finds it, installs it) or would it need to go through a security/procurement process?**
   - Goal: Determine whether to optimize for developer DX and virality or enterprise sales motions.

9. **What's your reaction to AGPL licensing for a security dependency? Dealbreaker, or fine as long as it's a standalone middleware?**
   - Goal: AGPL is a known friction point in enterprise. Determine whether a dual-license / commercial option is needed.

## Technical Depth (if the conversation goes there)

10. **Do your agents do multi-step tool-calling? If so, how do you track trust/provenance of data flowing between steps — or do you not?**
    - Goal: Open the door to discuss CaMeL-inspired data provenance — the most novel technical differentiator.

11. **How many distinct LLM call sites does your product have? Are we talking 2-3, or dozens?**
    - Goal: Determine whether the session API (multi-step agent wrapper) or the simple `pre()/post()` API is the right pitch.

## Meta / Relationship Questions

12. **If I built something that solved [the problem they described], would you be willing to try it on a non-critical path for a couple weeks and give me honest feedback?**
    - Goal: Convert the conversation into a design partner relationship.

13. **Who else in your network is wrestling with LLM security? Would you be open to an intro?**
    - Goal: Series B VPEs know other VPEs. One warm intro is worth more than 100 cold outreaches.

---

## Suggested Conversation Flow

1. **Start with questions 1-3** — validate the problem exists and is painful
2. **Move to 4-6** — understand how they'd evaluate and buy
3. **Close with 12-13** — convert to a design partner and get referrals
4. Only go into technical depth (10-11) if they signal genuine interest
5. Questions 7-9 are for reading the room on GTM and licensing
