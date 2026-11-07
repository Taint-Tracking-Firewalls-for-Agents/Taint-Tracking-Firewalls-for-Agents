"""Cybersecurity-themed CSS styling and visual tokens for Agent Firewall.

Color Palette:
- Midnight Black: #02070A (deep background)
- Electric Blue: #0297DE (primary accent)
- Deep Navy Slate: #07131B (card surface)
- Muted Slate: #0E1E2B (secondary surface)
- Cyan Highlight: #00D2FF
- Text Primary: #F1F5F9
- Text Secondary: #94A3B8
- Border: #142E42
- Emerald Green (Allow/Trusted): #10B981
- Amber (Ask/Human Approval): #F59E0B
- Crimson Red (Block/Untrusted): #EF4444
"""

CUSTOM_CSS = """
<style>
/* Main app background & layout */
.stApp {
    background-color: #02070A !important;
    color: #F1F5F9 !important;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}

/* Header & Typography */
h1, h2, h3, h4, h5, h6 {
    color: #F1F5F9 !important;
    font-weight: 600 !important;
    letter-spacing: -0.02em;
}

h1 {
    font-size: 2.1rem !important;
    border-bottom: 1px solid #142E42;
    padding-bottom: 0.6rem;
    margin-bottom: 1.2rem;
}

/* Electric Blue Glow & Accents */
.cyber-glow {
    text-shadow: 0 0 12px rgba(2, 151, 222, 0.45);
}

.electric-text {
    color: #0297DE !important;
    font-weight: 600;
}

/* Custom Card Container */
.cyber-card {
    background: linear-gradient(145deg, #07131B 0%, #0A1B27 100%);
    border: 1px solid #142E42;
    border-radius: 10px;
    padding: 1.25rem;
    margin-bottom: 1rem;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

.cyber-card:hover {
    border-color: #0297DE;
    box-shadow: 0 4px 24px rgba(2, 151, 222, 0.15);
}

/* Metric Display Card */
.metric-box {
    background: #07131B;
    border: 1px solid #142E42;
    border-top: 3px solid #0297DE;
    border-radius: 8px;
    padding: 1rem 1.2rem;
    text-align: left;
}

.metric-title {
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #94A3B8;
    margin-bottom: 0.3rem;
}

.metric-value {
    font-size: 1.85rem;
    font-weight: 700;
    color: #F1F5F9;
    line-height: 1.2;
}

.metric-caption {
    font-size: 0.8rem;
    color: #0297DE;
    margin-top: 0.3rem;
}

/* Security Status Badges - Accessible with both icons and colors */
.badge-trusted {
    display: inline-flex;
    align-items: center;
    background: rgba(16, 185, 129, 0.15);
    color: #10B981;
    border: 1px solid #10B981;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.05em;
}

.badge-untrusted {
    display: inline-flex;
    align-items: center;
    background: rgba(239, 68, 68, 0.15);
    color: #EF4444;
    border: 1px solid #EF4444;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.05em;
}

.badge-allow {
    display: inline-flex;
    align-items: center;
    background: rgba(2, 151, 222, 0.15);
    color: #0297DE;
    border: 1px solid #0297DE;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.05em;
}

.badge-block {
    display: inline-flex;
    align-items: center;
    background: rgba(239, 68, 68, 0.2);
    color: #F87171;
    border: 1px solid #EF4444;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.05em;
}

.badge-ask {
    display: inline-flex;
    align-items: center;
    background: rgba(245, 158, 11, 0.18);
    color: #FBBF24;
    border: 1px solid #F59E0B;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.05em;
}

/* Event timeline styling */
.timeline-item {
    border-left: 2px solid #142E42;
    padding-left: 1rem;
    margin-left: 0.5rem;
    margin-bottom: 0.9rem;
    position: relative;
}

.timeline-item::before {
    content: "";
    position: absolute;
    left: -5px;
    top: 5px;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #0297DE;
}

.timeline-item.blocked::before {
    background: #EF4444;
    box-shadow: 0 0 8px #EF4444;
}

.timeline-item.allowed::before {
    background: #10B981;
}

.timeline-item.tainted::before {
    background: #F59E0B;
}

/* Code & pre blocks */
pre, code {
    background-color: #061017 !important;
    border: 1px solid #142E42 !important;
    color: #E2E8F0 !important;
    border-radius: 6px;
}

/* Sidebar styling */
[data-testid="stSidebar"] {
    background-color: #07131B !important;
    border-right: 1px solid #142E42;
}

/* Input boxes & Select boxes */
.stSelectbox, .stTextInput, .stMultiSelect {
    color: #F1F5F9;
}

/* Buttons */
.stButton > button {
    background: linear-gradient(180deg, #0297DE 0%, #0178B3 100%) !important;
    color: #FFFFFF !important;
    font-weight: 600 !important;
    border: 1px solid #00B4FF !important;
    border-radius: 6px !important;
    padding: 0.45rem 1.1rem !important;
    box-shadow: 0 2px 8px rgba(2, 151, 222, 0.35) !important;
    transition: all 0.2s ease-in-out !important;
}

.stButton > button:hover {
    background: linear-gradient(180deg, #02A8F5 0%, #0297DE 100%) !important;
    box-shadow: 0 4px 14px rgba(2, 151, 222, 0.55) !important;
    transform: translateY(-1px);
}

/* Tables & Dataframes */
[data-testid="stDataFrame"] {
    background-color: #07131B;
    border: 1px solid #142E42;
    border-radius: 8px;
}

/* Tab styling */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    background-color: transparent;
    border-bottom: 1px solid #142E42;
}

.stTabs [data-baseweb="tab"] {
    height: 42px;
    border-radius: 6px 6px 0px 0px;
    background-color: #07131B;
    color: #94A3B8;
    border: 1px solid #142E42;
    border-bottom: none;
    padding: 0 16px;
    font-weight: 500;
}

.stTabs [aria-selected="true"] {
    background-color: #0D2232 !important;
    color: #00D2FF !important;
    border-color: #0297DE !important;
    border-bottom: 2px solid #0297DE !important;
    font-weight: 600;
}

/* Expander styling */
.streamlit-expanderHeader {
    background-color: #07131B !important;
    border: 1px solid #142E42 !important;
    border-radius: 6px !important;
    color: #F1F5F9 !important;
}
</style>
"""


def apply_theme():
    """Inject custom CSS into Streamlit document."""
    import streamlit as st
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
