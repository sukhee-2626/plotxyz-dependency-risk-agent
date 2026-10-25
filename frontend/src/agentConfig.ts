export type FieldType = "text" | "textarea" | "number" | "checkbox";

export interface AgentField {
  name: string;
  label: string;
  type: FieldType;
  rows?: number;
  placeholder?: string;
}

export interface AgentConfig {
  slug: string;
  title: string;
  tagline: string;
  purpose: string;
  accent: string;
  features: string[];
  limitations: string[];
  fields: AgentField[];
  sample: Record<string, string | number | boolean>;
  repo: string;
}

export const agent: AgentConfig = {
  "slug": "plotxyz-dependency-risk-agent",
  "title": "Dependency Risk",
  "tagline": "Know what your manifest is really pulling in.",
  "purpose": "Parses requirements or package.json files, reports pinning and source hygiene, and optionally queries OSV for authoritative advisories.",
  "accent": "#fbbf24",
  "features": [
    "Manifest parsing for pip and npm",
    "Pinning and provenance checks",
    "Optional OSV advisory lookup"
  ],
  "limitations": [
    "Offline mode does not claim to know advisories.",
    "OSV results depend on network availability and exact versions."
  ],
  "fields": [
    {
      "name": "manifest",
      "label": "Manifest",
      "type": "textarea",
      "rows": 8,
      "placeholder": ""
    },
    {
      "name": "ecosystem",
      "label": "Ecosystem (requirements or package)",
      "type": "text",
      "rows": 4,
      "placeholder": ""
    },
    {
      "name": "check_osv",
      "label": "Query OSV advisories",
      "type": "checkbox",
      "rows": 4,
      "placeholder": ""
    }
  ],
  "sample": {
    "manifest": "flask\nrequests==2.31.0\npyyaml>=6",
    "ecosystem": "requirements",
    "check_osv": false
  },
  "repo": "https://github.com/sukhee-2626/plotxyz-dependency-risk-agent"
};
