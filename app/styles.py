"""Obsidian Dark Mode DX-Grade Styling System for Agent Firewall.

Implements the <dashboard_aesthetics_system> guidelines:
- Fonts: Inter (labels) + JetBrains Mono (metrics, numbers, timestamps, hashes, code)
- Palette: 
    * 85% Canvas: Obsidian Midnight Black (#02070A), Deep Slate (#050B10, #081119)
    * 10% Structural: Hairline borders (rgba(255,255,255,0.08) / #132433), muted slate (#64748B)
    * 5% Intentional Action: Electric Blue (#0297DE), Precision Cyan (#00C2FF)
- Streamlit Padding Override: Compact, high-density padding (Linear / Bloomberg Terminal aesthetic)
- Micro-radii (4px-6px) and razor-thin hairline borders (1px)
"""

CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700;800&display=swap');

/* ==========================================================================
   1. STREAMLIT GLOBAL RESET & CONTAINER PADDING OVERRIDE
   ========================================================================== */
html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
    background-color: #02070A !important;
    color: #E2E8F0 !important;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}

/* Remove default Streamlit top gap and tighten content padding */
.block-container {
    padding-top: 1.5rem !important;
    padding-bottom: 2.5rem !important;
    padding-left: 2rem !important;
    padding-right: 2rem !important;
    max-width: 1480px !important;
}

header[data-testid="stHeader"] {
    background: transparent !important;
    height: 0px !important;
}

footer {
    display: none !important;
}

/* Atmospheric spatial depth with subtle radial lighting */
.stApp {
    background: radial-gradient(circle at 50% 0%, #06131D 0%, #02070A 70%) !important;
    background-attachment: fixed !important;
}

/* ==========================================================================
   2. TYPOGRAPHY & DATA READOUT
   ========================================================================== */
h1, h2, h3, h4, h5, h6 {
    font-family: 'Inter', sans-serif !important;
    color: #F8FAFC !important;
    letter-spacing: -0.025em !important;
    font-weight: 600 !important;
}

h1 {
    font-size: 1.75rem !important;
    margin-bottom: 0.8rem !important;
}

h2 {
    font-size: 1.35rem !important;
    margin-top: 1.2rem !important;
    margin-bottom: 0.6rem !important;
}

h3 {
    font-size: 1.1rem !important;
    margin-top: 1rem !important;
    margin-bottom: 0.5rem !important;
}

/* JetBrains Mono applied strictly to all metrics, code, timestamps, and tags */
.mono-metric, 
.metric-value, 
code, 
pre, 
.badge-code, 
.timestamp, 
.rule-tag {
    font-family: 'JetBrains Mono', monospace !important;
    font-feature-settings: "zero" 1, "tnum" 1 !important;
}

/* ==========================================================================
   3. OBSIDIAN CARD SURFACE & HAIRLINE BORDERS
   ========================================================================== */
.obsidian-card {
    background: #050B10;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 6px;
    padding: 1.1rem 1.25rem;
    margin-bottom: 0.85rem;
    transition: border-color 0.15s ease, background-color 0.15s ease;
    position: relative;
}

.obsidian-card:hover {
    border-color: rgba(2, 151, 222, 0.4);
    background: #071017;
}

/* Metric Display Card - Information Dense */
.metric-card-dx {
    background: #050B10;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-top: 2px solid #0297DE;
    border-radius: 6px;
    padding: 0.9rem 1.1rem;
    margin-bottom: 0.5rem;
    transition: all 0.15s ease;
}

.metric-card-dx:hover {
    border-color: rgba(2, 151, 222, 0.5);
    background: #07111A;
}

.metric-micro-label {
    font-size: 10px !important;
    text-transform: uppercase !important;
    letter-spacing: 0.12em !important;
    color: #64748B !important;
    font-weight: 600 !important;
    margin-bottom: 0.35rem !important;
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.metric-value-large {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 1.85rem !important;
    font-weight: 700 !important;
    color: #F8FAFC !important;
    line-height: 1.1 !important;
    letter-spacing: -0.03em !important;
}

.metric-delta-sub {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.72rem !important;
    margin-top: 0.35rem !important;
    color: #0297DE !important;
    display: flex;
    align-items: center;
    gap: 4px;
}

/* ==========================================================================
   4. REFINED ACCESSIBLE BADGES & TAGS
   ========================================================================== */
.status-pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.04em;
    padding: 2px 7px;
    border-radius: 4px;
    line-height: 1.4;
}

.pill-trusted {
    background: rgba(16, 185, 129, 0.08);
    color: #34D399;
    border: 1px solid rgba(16, 185, 129, 0.25);
}

.pill-untrusted {
    background: rgba(239, 68, 68, 0.08);
    color: #F87171;
    border: 1px solid rgba(239, 68, 68, 0.25);
}

.pill-allow {
    background: rgba(2, 151, 222, 0.08);
    color: #38BDF8;
    border: 1px solid rgba(2, 151, 222, 0.3);
}

.pill-block {
    background: rgba(239, 68, 68, 0.12);
    color: #FCA5A5;
    border: 1px solid rgba(239, 68, 68, 0.4);
}

.pill-ask {
    background: rgba(245, 158, 11, 0.1);
    color: #FBBF24;
    border: 1px solid rgba(245, 158, 11, 0.3);
}

/* ==========================================================================
   5. SIDEBAR HIERARCHY & CONTROLS
   ========================================================================== */
[data-testid="stSidebar"] {
    background-color: #04080D !important;
    border-right: 1px solid rgba(255, 255, 255, 0.07) !important;
}

[data-testid="stSidebar"] .block-container {
    padding-top: 2rem !important;
    padding-left: 1.25rem !important;
    padding-right: 1.25rem !important;
}

/* Sidebar Radio Navigation */
[data-testid="stSidebar"] .stRadio > div {
    gap: 4px !important;
}

[data-testid="stSidebar"] .stRadio label {
    background: transparent !important;
    border: 1px solid transparent !important;
    border-radius: 5px !important;
    padding: 6px 10px !important;
    margin-bottom: 2px !important;
    color: #94A3B8 !important;
    font-size: 0.88rem !important;
    font-weight: 500 !important;
    transition: all 0.15s ease !important;
}

[data-testid="stSidebar"] .stRadio label:hover {
    background: #08121A !important;
    color: #F1F5F9 !important;
    border-color: rgba(255, 255, 255, 0.06) !important;
}

/* Active navigation item */
[data-testid="stSidebar"] .stRadio label[data-checked="true"],
[data-testid="stSidebar"] .stRadio input:checked + div {
    color: #00D2FF !important;
    font-weight: 600 !important;
}

/* ==========================================================================
   6. HIGH-PRECISION BUTTONS & INPUT CONTROLS
   ========================================================================== */
.stButton > button {
    background: #0297DE !important;
    color: #FFFFFF !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 0.82rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.02em !important;
    border: 1px solid rgba(255, 255, 255, 0.15) !important;
    border-radius: 5px !important;
    padding: 0.45rem 1rem !important;
    box-shadow: none !important;
    transition: all 0.15s ease-in-out !important;
}

.stButton > button:hover {
    background: #02A8F5 !important;
    border-color: #38BDF8 !important;
    transform: translateY(-1px);
}

.stButton > button:active {
    transform: translateY(0);
}

/* Form Inputs, Selectboxes & Multiselect */
div[data-baseweb="select"] > div,
input, 
textarea {
    background-color: #050B10 !important;
    border: 1px solid rgba(255, 255, 255, 0.09) !important;
    border-radius: 5px !important;
    color: #F1F5F9 !important;
    font-size: 0.85rem !important;
    font-family: 'Inter', sans-serif !important;
}

div[data-baseweb="select"] > div:hover {
    border-color: rgba(2, 151, 222, 0.4) !important;
}

/* Dataframe & Tables */
[data-testid="stDataFrame"] {
    background-color: #04080D !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 6px !important;
    overflow: hidden;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    gap: 4px !important;
    border-bottom: 1px solid rgba(255, 255, 255, 0.08) !important;
    padding-bottom: 2px !important;
}

.stTabs [data-baseweb="tab"] {
    height: 36px !important;
    border-radius: 4px 4px 0 0 !important;
    background: transparent !important;
    color: #64748B !important;
    font-size: 0.82rem !important;
    font-weight: 500 !important;
    border: 1px solid transparent !important;
    padding: 0 14px !important;
}

.stTabs [data-baseweb="tab"]:hover {
    color: #CBD5E1 !important;
}

.stTabs [aria-selected="true"] {
    background: #050C12 !important;
    color: #0297DE !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-bottom: 2px solid #0297DE !important;
    font-weight: 600 !important;
}

/* Code and JSON blocks */
pre, code {
    background-color: #030609 !important;
    border: 1px solid rgba(255, 255, 255, 0.06) !important;
    border-radius: 4px !important;
    color: #38BDF8 !important;
    font-size: 0.82rem !important;
}

/* Streamlit Expanders */
.streamlit-expanderHeader {
    background-color: #050B10 !important;
    border: 1px solid rgba(255, 255, 255, 0.07) !important;
    border-radius: 5px !important;
    color: #CBD5E1 !important;
    font-size: 0.85rem !important;
}

.streamlit-expanderHeader:hover {
    border-color: rgba(2, 151, 222, 0.3) !important;
    color: #F8FAFC !important;
}

/* Horizontal Dividers */
hr {
    border-color: rgba(255, 255, 255, 0.06) !important;
    margin: 1.2rem 0 !important;
}
</style>
"""


def apply_theme():
    """Inject obsidian dark mode CSS styling system."""
    import streamlit as st
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
