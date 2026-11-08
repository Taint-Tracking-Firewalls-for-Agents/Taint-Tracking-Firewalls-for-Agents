"""Industrial / drafting-table design tokens and styling for Agent Firewall.

Mood: industrial / drafting-table / lab instrument cockpit.
Typography:
- Display: 'Big Shoulders Display' (weights 600, 800, 900)
- Body & Data: 'Martian Mono' (weights 400, 600)
Theme Palettes:
- Dark: 'Ink and lime' (#0A0A0F, #14141C, #C6F432, #F4F4FA)
- Light: 'Mint and navy' (#CDEFE0, #EAFBF3, #0B7A4B, #0A2540)
"""
from __future__ import annotations
import streamlit as st


def get_theme_css(theme: str = "dark") -> str:
    """Generate dynamic CSS tokens and rules for the active theme."""
    is_dark = theme.lower() == "dark"

    if is_dark:
        bg = "#0A0A0F"
        panel = "#14141C"
        panel_alt = "#1A1A24"
        ink = "#F4F4FA"
        muted = "#9B9BB0"
        line = "rgba(244,244,250,0.14)"
        trust = "#59A6FF"
        dye = "#C6F432"
        ok = "#59A6FF"
        ask = "#FFB84D"
        grid = "rgba(244,244,250,0.04)"
        stamp_ink = "#0A0A0F"
        dye_contrast = "#0A0A0F"
        btn_bg = "#1A1A24"
        btn_hover = "#242432"
        input_bg = "#14141C"
        input_border = "rgba(244,244,250,0.18)"
        input_color = "#F4F4FA"
    else:
        bg = "#CDEFE0"
        panel = "#EAFBF3"
        panel_alt = "#DCF7EB"
        ink = "#0A2540"
        muted = "#2C4A5A"
        line = "rgba(10,37,64,0.18)"
        trust = "#1B5FD6"
        dye = "#E11D48"
        ok = "#0B7A4B"
        ask = "#9A5B00"
        grid = "rgba(10,37,64,0.06)"
        stamp_ink = "#0A2540"
        dye_contrast = "#FFFFFF"
        btn_bg = "#EAFBF3"
        btn_hover = "#DCF7EB"
        input_bg = "#EAFBF3"
        input_border = "rgba(10,37,64,0.22)"
        input_color = "#0A2540"

    return f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Big+Shoulders+Display:wght@600;700;800;900&family=Martian+Mono:wght@400;500;600;700&display=swap');

:root {{
  --bg: {bg};
  --panel: {panel};
  --panel-alt: {panel_alt};
  --ink: {ink};
  --muted: {muted};
  --line: {line};
  --trust: {trust};
  --dye: {dye};
  --ok: {ok};
  --ask: {ask};
  --grid: {grid};
  --stamp-ink: {stamp_ink};
  --dye-contrast: {dye_contrast};
  --btn-bg: {btn_bg};
  --btn-hover: {btn_hover};
  --input-bg: {input_bg};
  --input-border: {input_border};
  --input-color: {input_color};
}}

/* Global Background and Typography */
html, body, .stApp {{
  background-color: var(--bg) !important;
  color: var(--ink) !important;
  font-family: 'Martian Mono', monospace !important;
  font-size: 13px !important;
  line-height: 1.55 !important;
  background-image: 
    linear-gradient(to right, var(--grid) 1px, transparent 1px),
    linear-gradient(to bottom, var(--grid) 1px, transparent 1px) !important;
  background-size: 32px 32px !important;
  -webkit-font-smoothing: antialiased;
}}

/* Streamlit Header & Sidebar Toggle Visibility */
header[data-testid="stHeader"] {{
  background: transparent !important;
  color: var(--ink) !important;
}}

/* Hide default Streamlit Deploy button and developer toolbar */
.stAppDeployButton,
[data-testid="stAppDeployButton"],
#MainMenu,
footer {{
  display: none !important;
}}

header[data-testid="stHeader"] * {{
  color: var(--ink) !important;
  fill: var(--ink) !important;
}}

/* Ensure sidebar collapse / expand chevron button is always visible & interactive */
[data-testid="stSidebarCollapsedControl"],
button[data-testid="stSidebarCollapsedControl"],
[data-testid="collapsedControl"] {{
  display: flex !important;
  visibility: visible !important;
  opacity: 1 !important;
  color: var(--ink) !important;
  background-color: var(--panel) !important;
  border: 1px solid var(--line) !important;
  border-radius: 4px !important;
  z-index: 999999 !important;
}}

[data-testid="stSidebarCollapsedControl"] * {{
  color: var(--ink) !important;
  fill: var(--ink) !important;
}}

.block-container {{
  max-width: 1200px !important;
  padding: 2rem 1.5rem 3rem 1.5rem !important;
  margin: 0 auto !important;
  animation: slideTransition 0.8s cubic-bezier(0.25, 1, 0.5, 1) forwards;
  will-change: transform, opacity;
}}

/* PowerPoint-style smooth slide transition: gentle incoming glide + soft cross-fade */
@keyframes slideTransition {{
  0% {{
    opacity: 0;
    transform: translate3d(24px, 0, 0);
  }}
  40% {{
    opacity: 0.6;
  }}
  100% {{
    opacity: 1;
    transform: translate3d(0, 0, 0);
  }}
}}

section[data-testid="stMain"] {{
  overflow-x: hidden !important;
}}

/* Typography */
.font-display {{
  font-family: 'Big Shoulders Display', sans-serif !important;
  text-transform: uppercase !important;
  letter-spacing: -0.01em !important;
}}

.font-mono {{
  font-family: 'Martian Mono', monospace !important;
}}

h1, h2, h3, h4 {{
  font-family: 'Big Shoulders Display', sans-serif !important;
  text-transform: uppercase !important;
  letter-spacing: -0.01em !important;
  color: var(--ink) !important;
  margin: 0 0 0.5rem 0 !important;
  padding: 0 !important;
}}

h1 {{
  font-size: clamp(3rem, 7vw, 5.5rem) !important;
  font-weight: 900 !important;
  line-height: 0.88 !important;
}}

h3 {{
  font-size: 1.6rem !important;
  font-weight: 800 !important;
}}

h4 {{
  font-size: 1.25rem !important;
  font-weight: 700 !important;
}}

p, span, label, div {{
  color: var(--ink);
}}

/* Cards & Panels */
.obsidian-card, .lab-panel {{
  background: var(--panel) !important;
  border: 1px solid var(--line) !important;
  border-radius: 4px;
  padding: 1rem 1.25rem;
  margin-bottom: 0.85rem;
  color: var(--ink) !important;
}}

.metric-card-dx {{
  background: var(--panel);
  border: 1px solid var(--line);
  border-top: 3px solid var(--trust);
  border-radius: 4px;
  padding: 1rem;
  margin-bottom: 0.5rem;
}}

.metric-micro-label {{
  font-family: 'Martian Mono', monospace !important;
  font-size: 11px !important;
  text-transform: uppercase !important;
  letter-spacing: 0.06em !important;
  color: var(--muted) !important;
  font-weight: 600 !important;
  margin-bottom: 0.25rem !important;
}}

.metric-value-large {{
  font-family: 'Big Shoulders Display', sans-serif !important;
  font-size: 2.8rem !important;
  font-weight: 900 !important;
  color: var(--ink) !important;
  line-height: 1 !important;
  letter-spacing: -0.02em !important;
}}

.metric-delta-sub {{
  font-family: 'Martian Mono', monospace !important;
  font-size: 11px !important;
  margin-top: 0.35rem !important;
}}

.mono-metric {{
  font-family: 'Martian Mono', monospace !important;
}}

/* Readout Strip */
.readout-strip {{
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 4px;
  margin-bottom: 2rem;
}}

.readout-cell {{
  padding: 1.25rem 1.5rem;
  border-right: 1px solid var(--line);
  display: flex;
  flex-direction: column;
}}

.readout-cell:last-child {{
  border-right: none;
}}

.readout-num {{
  font-family: 'Big Shoulders Display', sans-serif;
  font-size: 3.2rem;
  font-weight: 900;
  line-height: 0.9;
  color: var(--ink);
  letter-spacing: -0.02em;
}}

.readout-caption {{
  font-size: 11px;
  color: var(--muted);
  margin-top: 0.4rem;
  text-transform: uppercase;
}}

/* Status Pills */
.status-pill {{
  display: inline-flex;
  align-items: center;
  padding: 3px 8px;
  border-radius: 3px;
  font-size: 11px;
  font-weight: 600;
  font-family: 'Martian Mono', monospace;
  letter-spacing: 0.04em;
}}

.pill-trusted {{
  background: rgba(27, 95, 214, 0.12);
  color: var(--trust);
  border: 1px solid var(--trust);
}}

.pill-untrusted {{
  background: rgba(225, 29, 72, 0.12);
  color: var(--dye);
  border: 1px solid var(--dye);
}}

.pill-allow {{
  background: rgba(89, 166, 255, 0.14);
  color: var(--ok);
  border: 1px solid var(--ok);
}}

.pill-block {{
  background: rgba(225, 29, 72, 0.14);
  color: var(--dye);
  border: 1px solid var(--dye);
}}

.pill-ask {{
  background: rgba(154, 91, 0, 0.14);
  color: var(--ask);
  border: 1px solid var(--ask);
}}

/* Sidebar Styling */
section[data-testid="stSidebar"] {{
  background-color: var(--panel) !important;
  border-right: 1px solid var(--line) !important;
}}

section[data-testid="stSidebar"] * {{
  color: var(--ink) !important;
}}

/* ==========================================================================
   Comprehensive Form Controls & Dropdown Selectboxes (Zero Black Boxes in Light Theme)
   ========================================================================== */
.stSelectbox,
[data-testid="stSelectbox"],
div[data-baseweb="select"],
div[data-baseweb="select"] > div,
div[data-baseweb="select"] div[role="combobox"],
div[data-baseweb="select"] [data-testid="stSelectboxVirtualDropdown"] {{
  background-color: var(--input-bg) !important;
  border-color: var(--input-border) !important;
  color: var(--input-color) !important;
  border-radius: 3px !important;
}}

/* Force all inner text, value labels, placeholders and SVG icons in selectbox to inherit theme color */
[data-testid="stSelectbox"] div,
[data-testid="stSelectbox"] span,
[data-testid="stSelectbox"] p,
div[data-baseweb="select"] div,
div[data-baseweb="select"] span,
div[data-baseweb="select"] p,
div[data-baseweb="select"] svg {{
  color: var(--input-color) !important;
  fill: var(--input-color) !important;
  background-color: transparent !important;
}}

/* Dropdown popover menu & options list when clicked */
div[data-baseweb="popover"],
div[data-baseweb="popover"] > div,
div[data-baseweb="popover"] ul,
ul[role="listbox"],
ul[role="listbox"] li,
li[role="option"] {{
  background-color: var(--panel) !important;
  color: var(--ink) !important;
  border-color: var(--line) !important;
}}

ul[role="listbox"] li:hover,
ul[role="listbox"] li[aria-selected="true"],
li[role="option"]:hover,
li[role="option"][aria-selected="true"] {{
  background-color: var(--panel-alt) !important;
  color: var(--ink) !important;
}}

ul[role="listbox"] li span,
li[role="option"] span {{
  color: var(--ink) !important;
}}

/* Text Inputs, Textareas & Search Boxes */
.stTextInput,
[data-testid="stTextInput"],
div[data-baseweb="input"],
div[data-baseweb="input"] > div {{
  background-color: var(--input-bg) !important;
  border-color: var(--input-border) !important;
  color: var(--input-color) !important;
  border-radius: 3px !important;
}}

div[data-baseweb="input"] input,
input, textarea {{
  background-color: transparent !important;
  color: var(--input-color) !important;
}}

/* Sidebar Navigation Smooth Interactive Transitions */
[data-testid="stRadio"] div[role="radiogroup"] {{
  gap: 3px !important;
}}

[data-testid="stRadio"] label {{
  padding: 0.4rem 0.65rem !important;
  border-radius: 4px !important;
  transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
  margin-bottom: 2px !important;
  cursor: pointer !important;
}}

[data-testid="stRadio"] label:hover {{
  background-color: var(--panel-alt) !important;
  transform: translateX(3px) !important;
}}

[data-testid="stRadio"] label[data-checked="true"],
[data-testid="stRadio"] label:has(input:checked) {{
  background-color: var(--panel-alt) !important;
  border-left: 3px solid var(--trust) !important;
  padding-left: calc(0.65rem - 3px) !important;
}}

[data-testid="stRadio"] label,
[data-testid="stRadio"] div,
[data-testid="stRadio"] span,
[data-testid="stRadio"] p {{
  color: var(--ink) !important;
  font-family: 'Martian Mono', monospace !important;
  font-size: 12px !important;
}}

/* Buttons */
.stButton > button {{
  background-color: var(--btn-bg) !important;
  color: var(--ink) !important;
  border: 1px solid var(--line) !important;
  border-radius: 3px !important;
  font-family: 'Martian Mono', monospace !important;
  font-size: 12px !important;
  font-weight: 600 !important;
  transition: all 0.15s ease;
  padding: 0.5rem 1rem !important;
}}

.stButton > button:hover {{
  background-color: var(--btn-hover) !important;
  border-color: var(--trust) !important;
  color: var(--ink) !important;
}}

/* Policy Table */
.policy-table {{
  width: 100%;
  border-collapse: collapse;
  margin-top: 0.5rem;
  font-family: 'Martian Mono', monospace;
  font-size: 12px;
}}

.policy-table th {{
  text-align: left;
  padding: 0.75rem 1rem;
  border-bottom: 2px solid var(--line);
  color: var(--muted);
  text-transform: uppercase;
  font-size: 11px;
}}

.policy-table td {{
  padding: 0.75rem 1rem;
  border-bottom: 1px solid var(--line);
  color: var(--ink);
}}

.policy-table tr:hover {{
  background: var(--panel-alt);
}}

.privilege-meter {{
  display: inline-flex;
  gap: 3px;
  vertical-align: middle;
  margin-right: 8px;
}}

.privilege-meter .segment {{
  width: 7px;
  height: 12px;
  background: var(--line);
  border-radius: 1px;
}}

.privilege-meter .segment.filled {{
  background: var(--ok);
}}

.privilege-meter .segment.filled.dye {{
  background: var(--dye);
}}

/* Hero Trace & Animated Pipe Flow */
.trace-container {{
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 2px;
  padding: 2.25rem 2rem;
  margin-bottom: 2rem;
  position: relative;
  overflow: hidden;
}}

.trace-pipe-wrapper {{
  position: relative;
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  margin: 2.5rem 1.5rem 2rem 1.5rem;
}}

.pipe-track {{
  position: absolute;
  top: 19px;
  left: 20px;
  right: 20px;
  height: 4px;
  transform: translateY(-50%);
  z-index: 1;
  background: var(--line);
}}

.pipe-flow {{
  position: absolute;
  top: 19px;
  left: 20px;
  right: 20px;
  height: 4px;
  transform: translateY(-50%);
  z-index: 2;
  background: linear-gradient(to right, var(--trust) 0%, var(--trust) 50%, var(--dye) 50%, var(--dye) 100%);
  background-size: 100% 100%;
  animation: pipeFill 2.2s cubic-bezier(0.6, 0, 0.2, 1) forwards;
  clip-path: inset(0 100% 0 0);
}}

@keyframes pipeFill {{
  0% {{ clip-path: inset(0 100% 0 0); }}
  100% {{ clip-path: inset(0 0 0 0); }}
}}

.trace-step {{
  position: relative;
  z-index: 3;
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  width: 200px;
}}

.node-circle {{
  width: 38px;
  height: 38px;
  border-radius: 50%;
  background: var(--panel);
  border: 2px solid var(--line);
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: 'Big Shoulders Display', sans-serif;
  font-size: 1.3rem;
  font-weight: 800;
  color: var(--ink);
  margin-bottom: 0.85rem;
  transition: all 0.2s ease;
}}

.step-active-trust .node-circle {{
  border-color: var(--trust);
  color: var(--trust);
}}

.step-active-dye .node-circle {{
  border-color: var(--dye);
  color: var(--dye);
}}

.step-label {{
  font-size: 11px;
  color: var(--muted);
  margin-bottom: 0.35rem;
}}

.step-tool {{
  font-family: 'Martian Mono', monospace;
  font-size: 12px;
  font-weight: 600;
  color: var(--ink);
  margin-bottom: 0.45rem;
}}

.verdict-tag {{
  display: inline-block;
  font-family: 'Martian Mono', monospace;
  font-size: 11px;
  font-weight: 600;
  border: 1px solid currentColor;
  padding: 2px 7px;
  border-radius: 2px;
}}

.tag-allow {{ color: var(--ok); }}
.tag-taint {{ color: var(--ask); }}
.tag-block {{ color: var(--dye); }}

.blocked-stamp {{
  position: absolute;
  right: 2.2rem;
  top: 1.8rem;
  font-family: 'Big Shoulders Display', sans-serif;
  font-size: 2.4rem;
  font-weight: 900;
  color: var(--dye);
  border: 3px solid var(--dye);
  padding: 2px 14px;
  border-radius: 2px;
  letter-spacing: 0.08em;
  line-height: 0.95;
  transform: scale(1) rotate(-7deg);
  opacity: 1;
  animation: stampSlam 0.35s cubic-bezier(0.175, 0.885, 0.32, 1.275) 2.2s both;
  pointer-events: none;
}}

@keyframes stampSlam {{
  0% {{
    opacity: 0;
    transform: scale(2.2) rotate(-15deg);
  }}
  100% {{
    opacity: 1;
    transform: scale(1) rotate(-7deg);
  }}
}}

@media (prefers-reduced-motion: reduce) {{
  .block-container {{
    animation: none !important;
  }}
  .pipe-flow {{
    animation: none !important;
    clip-path: inset(0 0 0 0) !important;
  }}
  .blocked-stamp {{
    animation: none !important;
    opacity: 1 !important;
    transform: scale(1) rotate(-7deg) !important;
  }}
  [data-testid="stRadio"] label {{
    transition: none !important;
    transform: none !important;
  }}
}}


@media (max-width: 768px) {{
  .readout-strip {{
    grid-template-columns: 1fr 1fr;
  }}
  .blocked-stamp {{
    position: static;
    display: inline-block;
    margin: 1rem 0;
    font-size: 2rem;
  }}
}}
</style>
"""


def apply_theme(theme: str = "dark") -> None:
    """Inject industrial drafting-table stylesheet with theme color variables."""
    css = get_theme_css(theme)
    st.markdown(css, unsafe_allow_html=True)
