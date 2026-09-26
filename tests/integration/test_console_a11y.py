"""Accessibility guarantees of the web console (WCAG 2.2 AA).

These static checks lock in the structure that an axe-core audit verified (0 violations
across all 9 views x light/dark/high-contrast themes, see ACCESSIBILITY.md). They fail
if a change drops a label, landmark, live region, focus style or motion preference.
"""
import re
from html.parser import HTMLParser
from pathlib import Path

import httpx

HTML = (Path(__file__).parents[2] / "vault" / "admin" / "console.html").read_text(encoding="utf-8")


class _Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def _tags():
    p = _Tags()
    p.feed(HTML)
    return p.tags


def test_document_language_title_and_viewport():
    assert re.search(r'<html lang="en">', HTML)
    assert "<title>" in HTML and 'name="viewport"' in HTML
    assert "user-scalable=no" not in HTML and "maximum-scale" not in HTML  # zoom must stay allowed


def test_skip_link_landmarks_and_headings():
    assert 'class="skip" href="#main"' in HTML
    assert 'id="main" tabindex="-1"' in HTML  # focus target for skip link and view changes
    assert 'aria-label="Main navigation"' in HTML
    assert '<header class="top">' in HTML and '<aside class="side"' in HTML
    assert HTML.count('id="page-title"') >= 9  # every view has a focusable h1


def test_live_regions_for_screen_readers():
    assert 'role="status" aria-live="polite"' in HTML
    assert 'role="alert"' in HTML


def test_every_form_control_has_a_label():
    tags = _tags()
    labelled = {a.get("for") for t, a in tags if t == "label"}
    # controls built in JS templates: collect ids from the source too
    ids = set(re.findall(r'<input id="([\w-]+)"', HTML)) | set(re.findall(r'<select id="([\w-]+)"', HTML))
    labelled |= set(re.findall(r'<label for="([\w-]+)"', HTML))
    unlabelled = {i for i in ids if i not in labelled and i not in ("fi",)}  # fi = hidden file input behind a real button
    assert not unlabelled, f"inputs without <label for>: {unlabelled}"
    # checkboxes/radios are wrapped in their <label>
    for m in re.finditer(r'<input type="(checkbox|radio)"', HTML):
        before = HTML[max(0, m.start() - 200):m.start()]
        assert "<label" in before, "checkbox/radio must be inside a label"


def test_icons_are_hidden_and_buttons_are_named():
    assert 'aria-hidden="true" focusable="false"' in HTML  # decorative SVG icons
    for label in ("Delete bucket", "Delete ${esc(name)}", "Download ${esc(name)}", "Remove user"):
        assert f'aria-label="{label}' in HTML


def test_tables_have_captions_and_header_scopes():
    assert HTML.count("<caption") >= 7
    assert 'scope="col"' in HTML and 'scope="row"' in HTML


def test_progress_bars_and_dialog_are_accessible():
    assert 'role="progressbar" aria-valuemin="0" aria-valuemax="100"' in HTML
    assert '<dialog id="dlg" aria-labelledby="dlg-title" aria-describedby="dlg-body">' in HTML
    assert "showModal()" in HTML and "opener.focus()" in HTML  # focus returns to the trigger


def test_focus_motion_contrast_and_reflow_css():
    assert ":focus-visible{outline:3px solid" in HTML
    assert "prefers-reduced-motion" in HTML and 'data-motion="reduce"' in HTML
    assert "forced-colors:active" in HTML
    assert 'data-theme="contrast"' in HTML
    assert "min-height:44px" in HTML  # target size
    assert ".app>*{min-width:0}" in HTML and ".tbl{overflow-x:auto;border-radius:10px;position:relative}" in HTML


def test_auto_refresh_can_be_paused_and_never_steals_focus():
    assert 'id="live-toggle" aria-pressed=' in HTML
    assert "(!m.contains(a) || a === m)" in HTML


def test_console_page_is_served(server):
    r = httpx.get(f"{server.endpoint}/vault/console")
    assert r.status_code == 200 and 'lang="en"' in r.text
