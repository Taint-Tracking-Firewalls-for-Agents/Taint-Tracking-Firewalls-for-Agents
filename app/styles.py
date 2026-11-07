"""Industrial / drafting-table design tokens and styling for Agent Firewall.

Mood: industrial / drafting-table / lab instrument.
Typography:
- Display: 'Big Shoulders Display' (weights 600, 800)
- Body & Data: 'Martian Mono' (weights 400, 600)
Theme Tokens:
- Light: 'Mint and navy'
- Dark: 'Ink and lime'
"""

DYE_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Big+Shoulders+Display:wght@600;800;900&family=Martian+Mono:wght@400;600&display=swap');

/* ==========================================================================
   1. COLOR TOKENS & SYSTEM VARIABLES
   ========================================================================== */
:root {
  /* Default to Light: Mint and navy */
  --bg: #CDEFE0;
  --panel: #EAFBF3;
  --ink: #0A2540;
  --muted: #3F5F6E;
  --line: rgba(10,37,64,.17);
  --trust: #1B5FD6;
  --dye: #E11D48;
  --ok: #0B7A4B;
  --ask: #9A5B00;
  --grid: rgba(10,37,64,.06);
  --stamp-ink: #0A2540;
  --dye-contrast: #FFFFFF;
}

@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #0A0A0F;
    --panel: #14141C;
    --ink: #F4F4FA;
    --muted: #9B9BB0;
    --line: rgba(244,244,250,.14);
    --trust: #59A6FF;
    --dye: #C6F432;
    --ok: #C6F432;
    --ask: #FFB84D;
    --grid: rgba(244,244,250,.04);
    --stamp-ink: #0A0A0F;
    --dye-contrast: #0A0A0F;
  }
}

:root[data-theme="light"] {
  --bg: #CDEFE0;
  --panel: #EAFBF3;
  --ink: #0A2540;
  --muted: #3F5F6E;
  --line: rgba(10,37,64,.17);
  --trust: #1B5FD6;
  --dye: #E11D48;
  --ok: #0B7A4B;
  --ask: #9A5B00;
  --grid: rgba(10,37,64,.06);
  --stamp-ink: #0A2540;
  --dye-contrast: #FFFFFF;
}

:root[data-theme="dark"] {
  --bg: #0A0A0F;
  --panel: #14141C;
  --ink: #F4F4FA;
  --muted: #9B9BB0;
  --line: rgba(244,244,250,.14);
  --trust: #59A6FF;
  --dye: #C6F432;
  --ok: #C6F432;
  --ask: #FFB84D;
  --grid: rgba(244,244,250,.04);
  --stamp-ink: #0A0A0F;
  --dye-contrast: #0A0A0F;
}

/* ==========================================================================
   2. GLOBAL LAYOUT & 32px GRID BACKGROUND
   ========================================================================== */
html, body, .stApp {
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
}

.block-container {
  max-width: 1160px !important;
  padding: 2.5rem 1.5rem !important;
  margin: 0 auto !important;
}

header[data-testid="stHeader"] {
  display: none !important;
}

/* Remove default Streamlit shadows, borders & heavy rounding */
div[data-testid="stVerticalBlock"] > div {
  gap: 0 !important;
}

/* ==========================================================================
   3. TYPOGRAPHY
   ========================================================================== */
.font-display {
  font-family: 'Big Shoulders Display', sans-serif !important;
  text-transform: uppercase !important;
}

.font-mono {
  font-family: 'Martian Mono', monospace !important;
}

h1, h2, h3, h4 {
  font-family: 'Big Shoulders Display', sans-serif !important;
  text-transform: uppercase !important;
  letter-spacing: -0.01em !important;
  color: var(--ink) !important;
  margin: 0 !important;
  padding: 0 !important;
}

h1 {
  font-size: clamp(3.4rem, 8vw, 6.5rem) !important;
  font-weight: 800 !important;
  line-height: 0.84 !important;
}

/* ==========================================================================
   4. UI COMPONENTS: READOUT STRIP, PANELS & PIPES
   ========================================================================== */
.lab-panel {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 2px;
  position: relative;
}

/* Readout Strip: 1 joined bordered panel with 4 cells */
.readout-strip {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 2px;
  margin-bottom: 2rem;
}

.readout-cell {
  padding: 1.25rem 1.5rem;
  border-right: 1px solid var(--line);
  display: flex;
  flex-direction: column;
}

.readout-cell:last-child {
  border-right: none;
}

.readout-num {
  font-family: 'Big Shoulders Display', sans-serif;
  font-size: 3.4rem;
  font-weight: 800;
  line-height: 0.9;
  color: var(--ink);
  letter-spacing: -0.02em;
}

.readout-caption {
  font-size: 11px;
  color: var(--muted);
  margin-top: 0.4rem;
}

/* ==========================================================================
   5. SCENARIO TRACE & ORCHESTRATED MOTION (HERO)
   ========================================================================== */
.trace-container {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 2px;
  padding: 2.25rem 2rem;
  margin-bottom: 2rem;
  position: relative;
  overflow: hidden;
}

.trace-pipe-wrapper {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin: 3rem 1.5rem 2.5rem 1.5rem;
}

/* Base track pipe background */
.pipe-track {
  position: absolute;
  top: 50%;
  left: 0;
  right: 0;
  height: 6px;
  transform: translateY(-50%);
  z-index: 1;
  background: var(--line);
}

/* Animated Dual-Dye Flow Pipe */
.pipe-flow {
  position: absolute;
  top: 50%;
  left: 0;
  right: 0;
  height: 6px;
  transform: translateY(-50%);
  z-index: 2;
  background: linear-gradient(to right, var(--trust) 0%, var(--trust) 50%, var(--dye) 50%, var(--dye) 100%);
  background-size: 100% 100%;
  animation: pipeFill 2.2s cubic-bezier(0.6, 0, 0.2, 1) forwards;
  clip-path: inset(0 100% 0 0);
}

@keyframes pipeFill {
  0% { clip-path: inset(0 100% 0 0); }
  100% { clip-path: inset(0 0 0 0); }
}

.trace-step {
  position: relative;
  z-index: 3;
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  width: 200px;
}

.node-circle {
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
}

.step-active-trust .node-circle {
  border-color: var(--trust);
  color: var(--trust);
}

.step-active-dye .node-circle {
  border-color: var(--dye);
  color: var(--dye);
}

.step-label {
  font-size: 11px;
  color: var(--muted);
  margin-bottom: 0.35rem;
}

.step-tool {
  font-family: 'Martian Mono', monospace;
  font-size: 12px;
  font-weight: 600;
  color: var(--ink);
  margin-bottom: 0.45rem;
}

.verdict-tag {
  display: inline-block;
  font-family: 'Martian Mono', monospace;
  font-size: 11px;
  font-weight: 600;
  border: 1px solid currentColor;
  padding: 2px 7px;
  border-radius: 2px;
}

.tag-allow { color: var(--ok); }
.tag-taint { color: var(--ask); }
.tag-block { color: var(--dye); }

/* SLAMMING BLOCKED STAMP */
.blocked-stamp {
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
}

@keyframes stampSlam {
  0% {
    opacity: 0;
    transform: scale(2.2) rotate(-15deg);
  }
  100% {
    opacity: 1;
    transform: scale(1) rotate(-7deg);
  }
}

/* Respect prefers-reduced-motion */
@media (prefers-reduced-motion: reduce) {
  .pipe-flow {
    animation: none !important;
    clip-path: inset(0 0 0 0) !important;
  }
  .blocked-stamp {
    animation: none !important;
    opacity: 1 !important;
    transform: scale(1) rotate(-7deg) !important;
  }
}

/* ==========================================================================
   6. POLICY MATRIX & 5-SEGMENT PRIVILEGE METER
   ========================================================================== */
.table-wrapper {
  overflow-x: auto;
  border: 1px solid var(--line);
  background: var(--panel);
  border-radius: 2px;
  margin-bottom: 1.25rem;
}

.policy-table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
  font-size: 12px;
}

.policy-table th {
  padding: 12px 16px;
  border-bottom: 1px solid var(--line);
  color: var(--muted);
  font-weight: 600;
  font-size: 11px;
}

.policy-table td {
  padding: 12px 16px;
  border-bottom: 1px solid var(--line);
  color: var(--ink);
}

.policy-table tr:last-child td {
  border-bottom: none;
}

/* 5-segment privilege meter */
.privilege-meter {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  margin-right: 8px;
}

.segment {
  width: 7px;
  height: 9px;
  background: var(--line);
  border-radius: 1px;
}

.segment.filled {
  background: var(--ink);
}

.segment.filled.dye {
  background: var(--dye);
}

/* Status Pill */
.status-pill-head {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  border: 1px solid var(--line);
  background: var(--panel);
  padding: 5px 12px;
  border-radius: 20px;
  font-size: 11px;
  color: var(--ink);
}

.status-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--ok);
}

/* Theme Switcher */
.theme-switch-btn {
  background: transparent;
  border: 1px solid var(--line);
  color: var(--ink);
  font-family: 'Martian Mono', monospace;
  font-size: 11px;
  padding: 4px 10px;
  border-radius: 2px;
  cursor: pointer;
}

.theme-switch-btn:focus-visible {
  outline: 2px solid var(--trust);
}

/* ==========================================================================
   7. MOBILE RESPONSIVENESS (360px+)
   ========================================================================== */
@media (max-width: 768px) {
  .readout-strip {
    grid-template-columns: repeat(2, 1fr);
  }
  .readout-cell:nth-child(2) {
    border-right: none;
  }
  .readout-cell:nth-child(1), .readout-cell:nth-child(2) {
    border-bottom: 1px solid var(--line);
  }

  .trace-pipe-wrapper {
    flex-direction: column;
    margin: 1.5rem 0;
    gap: 2rem;
  }

  .pipe-track, .pipe-flow {
    display: none;
  }

  .blocked-stamp {
    position: static;
    display: inline-block;
    margin: 1rem auto 0 auto;
    font-size: 1.8rem;
  }
}
</style>
"""


def apply_theme():
    """Inject industrial drafting-table stylesheet."""
    import streamlit as st
    st.markdown(DYE_CSS, unsafe_allow_html=True)
