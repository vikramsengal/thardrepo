class DNSOODALoop:

    def observe(self, query: dict) -> dict:
        """Step 1–3: Capture raw DNS event."""
        return {
            "domain": query["qname"],
            "client": query["src_ip"],
            "type":   query["qtype"],
            "rcode":  query["rcode"],
            "ts":     query["timestamp"],
        }

    def orient(self, obs: dict) -> dict:
        """Step 4–5: Enrich and score."""
        domain = obs["domain"]
        score  = threat_intel.lookup(domain)       # 0.0 – 1.0
        age    = whois.domain_age_days(domain)
        dga    = dga_model.predict(domain)          # bool
        return {**obs, "score": score, "age": age, "dga": dga}

    def decide(self, analysis: dict) -> str:
        """Step 5: Choose action."""
        if analysis["score"] > 0.85 or analysis["dga"]:
            return "block"
        if analysis["score"] > 0.5 or analysis["age"] < 7:
            return "alert"
        return "allow"

    def act(self, action: str, analysis: dict):
        """Step 6: Enforce and feed back."""
        domain = analysis["domain"]
        if action == "block":
            dns_firewall.sinkhole(domain)
            siem.alert(f"Blocked DNS: {domain}", severity="high")
        elif action == "alert":
            siem.alert(f"Suspicious DNS: {domain}", severity="medium")
        threat_intel.feedback(domain, action)   # tighten the model

    def run(self, query: dict):
        obs      = self.observe(query)
        analysis = self.orient(obs)
        action   = self.decide(analysis)
        self.act(action, analysis)