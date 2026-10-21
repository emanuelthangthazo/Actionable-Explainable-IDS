"""AXIDS Interactive SOC Alert Triage CLI tool.

Provides an interactive terminal interface for security analysts to inspect network flows,
review ML confidence, examine SHAP feature attribution bar charts, and triage LLM-generated
actionable SOC alerts grounded in the security Knowledge Base.

Usage:
    python -m tools.triage_cli --count 5 --seed 7
"""

import argparse
import json
import logging
import random
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from llm.alert_builder import process_flow_to_alert
from llm.config import FALLBACK_EXPLANATION, FALLBACK_RECOMMENDATION
from llm.ollama_client import OllamaClient, OllamaConnectionError, OllamaError
from test_pipeline import BENIGN_LABEL, load_test_set_raw

logger = logging.getLogger("axids.triage_cli")
console = Console()


def sample_triage_flows(
    df_test: pd.DataFrame,
    feature_columns: List[str],
    count: int = 5,
    seed: int = 7,
) -> List[Dict[str, Any]]:
    """Sample a balanced, representative mix of flows (BENIGN + distinct attacks) from the test set.

    Reuses the data filtering and sampling principles from test_pipeline.py.

    Args:
        df_test: Raw held-out test DataFrame from load_test_set_raw().
        feature_columns: Required model feature columns.
        count: Total number of flows to sample.
        seed: Random seed for reproducibility.

    Returns:
        List of dicts containing 'flow_dict', 'true_label', and 'sample_index'.
    """
    rng = random.Random(seed)
    available_cols = [c for c in feature_columns if c in df_test.columns]
    
    # Filter valid numeric rows without inf/nan
    df_clean = df_test.dropna(subset=available_cols + ["Label"]).copy()
    num_data = df_clean[available_cols].select_dtypes(include=[np.number]).values
    inf_mask = np.isinf(num_data).any(axis=1)
    df_clean = df_clean[~inf_mask]

    # Calculate partition: ~40% benign, ~60% attack
    n_benign = max(1, int(round(count * 0.4))) if count > 1 else 0
    n_attack = count - n_benign

    samples_list: List[pd.DataFrame] = []

    # 1. Sample Benign
    benign_rows = df_clean[df_clean["Label"] == BENIGN_LABEL]
    if len(benign_rows) > 0 and n_benign > 0:
        n_b = min(n_benign, len(benign_rows))
        samples_list.append(benign_rows.sample(n=n_b, random_state=seed))

    # 2. Sample Attacks across distinct classes
    attack_rows = df_clean[df_clean["Label"] != BENIGN_LABEL]
    attack_classes = [c for c in attack_rows["Label"].unique() if c.strip() and c != BENIGN_LABEL]
    rng.shuffle(attack_classes)

    attack_sample_list: List[pd.DataFrame] = []
    for atk_class in attack_classes:
        if len(attack_sample_list) >= n_attack:
            break
        class_rows = attack_rows[attack_rows["Label"] == atk_class]
        if len(class_rows) > 0:
            attack_sample_list.append(class_rows.sample(n=1, random_state=seed))

    # If we need more attack rows than distinct classes available, sample randomly from all attacks
    if len(attack_sample_list) < n_attack:
        remaining = n_attack - len(attack_sample_list)
        if len(attack_rows) > 0:
            attack_sample_list.append(attack_rows.sample(n=min(remaining, len(attack_rows)), random_state=seed))

    if attack_sample_list:
        samples_list.append(pd.concat(attack_sample_list, ignore_index=True))

    if not samples_list:
        raise RuntimeError("No valid flows could be sampled from the test set.")

    combined = pd.concat(samples_list, ignore_index=True)
    combined = combined.sample(frac=1, random_state=seed).reset_index(drop=True)

    samples: List[Dict[str, Any]] = []
    for i, row in combined.head(count).iterrows():
        true_label = row["Label"]
        flow_dict = row.drop(labels=["Label"]).to_dict()
        samples.append({
            "flow_dict": flow_dict,
            "true_label": true_label,
            "sample_index": int(i),
        })

    return samples


def render_shap_bar_chart(top_features: List[Dict[str, Any]], max_bar_len: int = 16) -> Table:
    """Render a terminal horizontal bar chart of SHAP feature attributions using Rich."""
    table = Table(title="[bold]Top Contributing Flow Features (SHAP Attributions)[/bold]", expand=True, show_header=True)
    table.add_column("Feature", style="bold cyan", ratio=3)
    table.add_column("Value", justify="right", style="white", ratio=2)
    table.add_column("Impact", justify="right", style="magenta", ratio=2)
    table.add_column("Attribution Chart", style="bold", ratio=4)
    table.add_column("Direction", justify="center", ratio=2)

    if not top_features:
        table.add_row("(No features available)", "-", "-", "-", "-")
        return table

    max_shap = max((abs(f.get("shap_value", 0.0)) for f in top_features), default=1.0)
    if max_shap == 0.0:
        max_shap = 1.0

    for f in top_features:
        name = f.get("feature", "Unknown")
        val = f.get("feature_value", 0.0)
        shap_val = f.get("shap_value", 0.0)
        direction = f.get("direction", "TOWARD")

        val_str = f"{val:,.4f}" if isinstance(val, (int, float)) else str(val)
        impact_str = f"{shap_val:+.4f}"

        # Relative bar rendering
        bar_len = max(1, int(round((abs(shap_val) / max_shap) * max_bar_len)))
        bar_chars = "█" * bar_len

        if direction == "TOWARD":
            bar_text = f"[bold red]{bar_chars}[/bold red]"
            dir_text = "[bold white on red] TOWARD [/bold white on red]"
        else:
            bar_text = f"[bold blue]{bar_chars}[/bold blue]"
            dir_text = "[bold white on blue] AWAY [/bold white on blue]"

        table.add_row(name, val_str, impact_str, bar_text, dir_text)

    return table


def render_severity_badge(severity: Optional[str], is_attack: bool) -> Text:
    """Generate a styled severity badge text."""
    sev_str = (severity or "unknown").lower()
    badge = Text()

    if not is_attack or sev_str == "none":
        badge.append(" BENIGN / NORMAL ", style="bold white on green")
    elif sev_str == "critical":
        badge.append(" CRITICAL SEVERITY ", style="bold white on dark_red")
    elif sev_str == "high":
        badge.append(" HIGH SEVERITY ", style="bold white on red")
    elif sev_str == "medium":
        badge.append(" MEDIUM SEVERITY ", style="bold black on yellow")
    elif sev_str == "low":
        badge.append(" LOW SEVERITY ", style="bold white on blue")
    else:
        badge.append(f" {sev_str.upper()} ", style="bold white on grey50")

    return badge


def display_flow_alert(flow_num: int, total_flows: int, true_label: str, alert: Dict[str, Any]) -> None:
    """Render the primary formatted SOC triage alert panel for a single flow."""
    pred = alert.get("prediction", {})
    pred_class = pred.get("attack_class", "UNKNOWN")
    conf = pred.get("confidence", 0.0)
    is_attack = pred.get("is_attack", False)

    shap_features = alert.get("explainability", {}).get("top_features", [])
    alert_body = alert.get("alert", {})
    severity = alert_body.get("severity")
    explanation = alert_body.get("explanation", FALLBACK_EXPLANATION)
    recommendation = alert_body.get("recommendation", FALLBACK_RECOMMENDATION)
    playbook_actions = alert_body.get("mitigation_playbook", {}).get("actions", [])
    sources = alert_body.get("sources", [])
    retrieval_ctx = alert.get("retrieval_context", {})
    metadata = alert.get("metadata", {})
    gen_status = metadata.get("generation_status", "unknown")

    # Header title
    status_symbol = "🚨" if is_attack else "🛡️"
    header_text = Text()
    header_text.append(f"{status_symbol} FLOW {flow_num} OF {total_flows} — ", style="bold cyan")
    header_text.append(f"Predicted: {pred_class} ", style="bold yellow" if is_attack else "bold green")
    header_text.append(f"({conf:.2%} confidence)", style="bold white")

    # Match indicator
    match = (pred_class == true_label)
    match_str = "[bold green]MATCH[/bold green]" if match else "[bold red]MISMATCH[/bold red]"

    # Sub-header info table
    info_table = Table.grid(padding=(0, 2))
    info_table.add_column("Key", style="bold white")
    info_table.add_column("Value")
    
    info_table.add_row("True Label:", f"{true_label} ({match_str})")
    info_table.add_row("Severity Level:", render_severity_badge(severity, is_attack))
    info_table.add_row("Knowledge Base Match:", f"{retrieval_ctx.get('match_type', 'none').upper()} ({', '.join(retrieval_ctx.get('kb_files', []))})")
    info_table.add_row("Model / LLM:", f"{metadata.get('model', 'XGBoost')} + {metadata.get('llm', 'Llama 3.2')}")

    # Check for degraded generation status
    degraded_panel = None
    if gen_status != "success" or explanation == FALLBACK_EXPLANATION:
        degraded_panel = Panel(
            f"[bold yellow]⚠️ LLM Generation Degraded ({gen_status})[/bold yellow]\n"
            "Ollama service was unavailable, timed out, or returned fallback prose. Showing standard baseline.",
            style="yellow",
            border_style="yellow",
        )

    # SHAP feature table
    shap_table = render_shap_bar_chart(shap_features)

    # Explanation text
    exp_panel = Panel(
        explanation,
        title="[bold]SOC Flow Analysis (SHAP & Profile Grounding)[/bold]",
        style="white",
        border_style="cyan",
    )

    # Recommendation & Actions
    rec_content = Text()
    rec_content.append(f"{recommendation}\n\n", style="white")
    if playbook_actions:
        rec_content.append("Recommended Playbook Actions:\n", style="bold yellow")
        for act in playbook_actions:
            rec_content.append(f"  • {act}\n", style="white")
    else:
        rec_content.append("No specific incident containment required (Normal/Benign traffic).\n", style="dim")

    if sources:
        rec_content.append(f"\nReferences & MITRE Links: {', '.join(sources)}", style="dim cyan")

    rec_panel = Panel(
        rec_content,
        title="[bold]Actionable Incident Response Playbook[/bold]",
        style="white",
        border_style="green" if not is_attack else "red",
    )

    # Print combined layout
    console.print("\n" + "=" * 80)
    console.print(header_text)
    console.print("=" * 80)
    console.print(info_table)
    if degraded_panel:
        console.print(degraded_panel)
    console.print()
    console.print(shap_table)
    console.print()
    console.print(exp_panel)
    console.print()
    console.print(rec_panel)


def display_detail_view(alert: Dict[str, Any]) -> None:
    """Display comprehensive raw SHAP attributions and retrieval context."""
    console.print("\n" + "─" * 80)
    console.print("[bold cyan]🔍 DETAILED FLOW & KNOWLEDGE BASE RETRIEVAL CONTEXT[/bold cyan]")
    console.print("─" * 80)

    top_features = alert.get("explainability", {}).get("top_features", [])
    if top_features:
        det_table = Table(title="Feature Attribution Vector", expand=True)
        det_table.add_column("Feature", style="cyan")
        det_table.add_column("Value", justify="right")
        det_table.add_column("SHAP Impact", justify="right", style="magenta")
        det_table.add_column("Direction", justify="center")

        for f in top_features:
            det_table.add_row(
                f.get("feature", "Unknown"),
                str(f.get("feature_value", 0.0)),
                f"{f.get('shap_value', 0.0):+.6f}",
                f.get("direction", "TOWARD"),
            )
        console.print(det_table)

    retrieval_context = alert.get("retrieval_context", {})
    console.print(Panel(
        f"Match Type: {retrieval_context.get('match_type')}\n"
        f"KB Files: {', '.join(retrieval_context.get('kb_files', []))}\n"
        f"Sources: {', '.join(alert.get('alert', {}).get('sources', []))}",
        title="[bold]Raw Knowledge Retrieval Metadata[/bold]",
        border_style="blue",
    ))
    console.print("─" * 80 + "\n")


def display_raw_json(alert: Dict[str, Any]) -> None:
    """Display formatted syntax-highlighted alert JSON."""
    raw_str = json.dumps(alert, indent=2)
    syntax = Syntax(raw_str, "json", theme="monokai", line_numbers=True)
    console.print("\n" + "─" * 80)
    console.print("[bold yellow]📄 RAW ACTIONABLE ALERT JSON[/bold yellow]")
    console.print("─" * 80)
    console.print(syntax)
    console.print("─" * 80 + "\n")


def run_triage_loop(
    count: int = 5,
    seed: int = 7,
    models_dir: str = "models",
    interactive: bool = True,
) -> None:
    """Main execution loop for the triage CLI."""
    console.print(Panel.fit(
        "[bold cyan]AXIDS — Actionable Explainable Intrusion Detection System[/bold cyan]\n"
        "[dim]Interactive SOC Flow Triage & Incident Response Console[/dim]",
        border_style="cyan",
    ))

    # 1. Check Ollama availability gracefully
    try:
        ollama_client = OllamaClient(timeout=25.0)
        # Quick ping test
        ollama_client.generate(prompt="ping", system="Respond JSON: {\"status\": \"ok\"}", format_json=True)
        console.print("[bold green]✔ Local Ollama Llama 3.2 connected on http://localhost:11434[/bold green]")
    except OllamaConnectionError:
        console.print(Panel(
            "[bold red]⚠️ Ollama is not currently reachable on http://localhost:11434[/bold red]\n"
            "Please ensure Ollama is running (`ollama serve`) and Llama 3.2 is pulled (`ollama pull llama3.2`).\n"
            "[yellow]The triage tool will proceed using graceful fallback explanations.[/yellow]",
            border_style="red",
        ))
    except Exception as exc:
        console.print(f"[yellow]Ollama check notice: {exc}. Proceeding with default handler.[/yellow]")

    # 2. Check model artifacts and feature columns
    features_path = Path(models_dir) / "feature_columns.json"
    if not features_path.exists():
        console.print(f"[bold red]Error: Required feature columns artifact missing at {features_path}[/bold red]")
        sys.exit(1)

    with open(features_path, "r", encoding="utf-8") as f:
        feature_columns: List[str] = json.load(f)

    # 3. Load held-out test data
    console.print(f"\n[bold]Loading test flows from CIC-IDS2017 held-out test set...[/bold]")
    df_test = load_test_set_raw()

    # 4. Sample flows
    samples = sample_triage_flows(df_test, feature_columns, count=count, seed=seed)
    total_flows = len(samples)
    console.print(f"[bold green]Sampled {total_flows} flows for interactive triage session.[/bold green]\n")

    # 5. Interactive triage loop
    for i, sample in enumerate(samples, start=1):
        true_label = sample["true_label"]
        flow_dict = sample["flow_dict"]

        with console.status(f"[bold cyan]Processing Flow {i}/{total_flows} through ML + SHAP + RAG + LLM...[/bold cyan]"):
            alert = process_flow_to_alert(
                flow_data=flow_dict,
                models_dir=models_dir,
                top_k=5,
            )

        display_flow_alert(
            flow_num=i,
            total_flows=total_flows,
            true_label=true_label,
            alert=alert,
        )

        if not interactive:
            continue

        # Sub-prompt loop for current flow
        while True:
            console.print("\n[bold]Triage Actions:[/bold] [cyan][n][/cyan] Next Flow  |  [cyan][d][/cyan] Detailed Context  |  [cyan][r][/cyan] Raw Alert JSON  |  [cyan][q][/cyan] Quit")
            choice = Prompt.ask(
                "Select action",
                choices=["n", "d", "r", "q"],
                default="n",
                show_choices=False,
            ).strip().lower()

            if choice == "n":
                break
            elif choice == "d":
                display_detail_view(alert)
            elif choice == "r":
                display_raw_json(alert)
            elif choice == "q":
                console.print("\n[bold cyan]Exiting AXIDS Triage Session. Stay secure![/bold cyan]")
                return

    console.print("\n[bold green]🎉 Triage session complete for all sampled flows.[/bold green]")


def main() -> None:
    parser = argparse.ArgumentParser(description="AXIDS Interactive SOC Alert Triage CLI tool.")
    parser.add_argument("--count", type=int, default=5, help="Number of flows to sample (default: 5)")
    parser.add_argument("--seed", type=int, default=7, help="Random seed for flow sampling (default: 7)")
    parser.add_argument("--models-dir", type=str, default="models", help="Directory with trained model artifacts")
    parser.add_argument("--non-interactive", action="store_true", help="Run without prompt pauses (for batch/testing)")

    args = parser.parse_args()

    try:
        run_triage_loop(
            count=args.count,
            seed=args.seed,
            models_dir=args.models_dir,
            interactive=not args.non_interactive,
        )
    except KeyboardInterrupt:
        console.print("\n[dim]Triage session interrupted by user.[/dim]")
    except Exception as exc:
        console.print(f"\n[bold red]Triage CLI encountered an error:[/bold red] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
