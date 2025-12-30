"""
Évaluation complète du LLM Firewall
Génère un rapport détaillé des performances
"""

import json
import time
from pathlib import Path
from firewall import LLMFirewall
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix


def load_test_data(dataset_path="data/threat_dataset.json"):
    """Charge les données de test"""
    with open(dataset_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    test_cases = []
    for category, prompts in data.items():
        is_threat = (category != 'safe')
        for prompt in prompts:
            test_cases.append({
                'prompt': prompt,
                'category': category,
                'is_threat': is_threat
            })
    
    return test_cases


def evaluate_firewall(firewall, test_cases):
    """Évalue le firewall sur tous les cas de test"""
    print("Lancement de l'évaluation...")
    
    results = []
    latencies = []
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"  [{i}/{len(test_cases)}] Test en cours.. .", end='\r')
        
        result = firewall.check_prompt(test_case['prompt'])
        
        results.append({
            'prompt': test_case['prompt'],
            'true_label': test_case['category'],
            'is_threat_true': test_case['is_threat'],
            'is_threat_pred': not result['safe'],
            'predicted_category': result['threat_type'],
            'confidence': result['confidence'],
            'latency_ms': result['latency_ms'],
            'method': result['method']
        })
        
        latencies.append(result['latency_ms'])
    
    print("\nÉvaluation terminée!")
    return results, latencies


def compute_metrics(results):
    """Calcule les métriques de performance"""
    y_true = [r['is_threat_true'] for r in results]
    y_pred = [r['is_threat_pred'] for r in results]
    
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)
    
    return {
        'accuracy':  accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'confusion_matrix': cm
    }


def generate_report(metrics, latencies, results, output_path="reports/evaluation_report.md"):
    """Génère un rapport Markdown"""
    Path("reports").mkdir(exist_ok=True)
    
    avg_latency = sum(latencies) / len(latencies)
    max_latency = max(latencies)
    min_latency = min(latencies)
    
    # Statistiques par méthode
    method_stats = {}
    for r in results:
        method = r['method'] or 'none'
        method_stats[method] = method_stats.get(method, 0) + 1
    
    # Construction du rapport
    report = "# 📊 LLM Firewall - Rapport d'Évaluation\n\n"
    report += "## 🎯 Métriques Globales\n\n"
    report += "| Métrique | Score |\n"
    report += "|----------|-------|\n"
    report += f"| **Accuracy** | **{metrics['accuracy']*100:.2f}%** |\n"
    report += f"| **Precision** | **{metrics['precision']*100:.2f}%** |\n"
    report += f"| **Recall** | **{metrics['recall']*100:.2f}%** |\n"
    report += f"| **F1-Score** | **{metrics['f1_score']*100:.2f}%** |\n\n"
    
    report += "## ⚡ Performance de Latence\n\n"
    report += "| Statistique | Valeur |\n"
    report += "|-------------|--------|\n"
    report += f"| **Latence moyenne** | {avg_latency:.2f} ms |\n"
    report += f"| **Latence min** | {min_latency:.2f} ms |\n"
    report += f"| **Latence max** | {max_latency:.2f} ms |\n\n"
    
    report += "## 📈 Matrice de Confusion\n\n"
    report += "```\n"
    report += "                 Prédit Négatif    Prédit Positif\n"
    report += f"Réel Négatif         {metrics['confusion_matrix'][0][0]}                  {metrics['confusion_matrix'][0][1]}\n"
    report += f"Réel Positif         {metrics['confusion_matrix'][1][0]}                  {metrics['confusion_matrix'][1][1]}\n"
    report += "```\n\n"
    
    report += "**Légende:**\n"
    report += f"- True Negatives (TN): {metrics['confusion_matrix'][0][0]}\n"
    report += f"- False Positives (FP): {metrics['confusion_matrix'][0][1]}\n"
    report += f"- False Negatives (FN): {metrics['confusion_matrix'][1][0]}\n"
    report += f"- True Positives (TP): {metrics['confusion_matrix'][1][1]}\n\n"
    
    report += "## 🔍 Détection par Méthode\n\n"
    report += "| Méthode | Nombre de détections |\n"
    report += "|---------|---------------------|\n"
    
    for method, count in method_stats.items():
        report += f"| {method} | {count} |\n"
    
    report += f"\n## 📋 Cas de Test\n\n"
    report += f"**Total de cas testés:** {len(results)}\n\n"
    report += "### Exemples de Détections Correctes\n\n"
    
    # Exemples de TP
    true_positives = [r for r in results if r['is_threat_true'] and r['is_threat_pred']][: 3]
    for i, tp in enumerate(true_positives, 1):
        report += f"**{i}. ** `{tp['prompt'][: 60]}... `\n"
        report += f"   - Catégorie: {tp['true_label']}\n"
        report += f"   - Confiance: {tp['confidence']:.2%}\n"
        report += f"   - Méthode: {tp['method']}\n\n"
    
    report += "### Faux Positifs (à investiguer)\n\n"
    
    # Faux positifs
    false_positives = [r for r in results if not r['is_threat_true'] and r['is_threat_pred']]
    if false_positives:
        for i, fp in enumerate(false_positives[: 3], 1):
            report += f"**{i}.** `{fp['prompt'][:60]}...`\n"
            report += f"   - Confiance: {fp['confidence']:. 2%}\n"
            report += f"   - Méthode: {fp['method']}\n\n"
    else:
        report += "✅ Aucun faux positif détecté!\n\n"
    
    report += "### Faux Négatifs (à investiguer)\n\n"
    
    # Faux négatifs
    false_negatives = [r for r in results if r['is_threat_true'] and not r['is_threat_pred']]
    if false_negatives:
        for i, fn in enumerate(false_negatives[: 3], 1):
            report += f"**{i}.** `{fn['prompt'][:60]}...`\n"
            report += f"   - Catégorie attendue: {fn['true_label']}\n\n"
    else:
        report += "✅ Aucun faux négatif détecté!\n\n"
    
    report += "\n---\n\n"
    report += f"**Rapport généré le:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
    report += "**Version:** LLM Firewall v2.0\n"
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"\n📄 Rapport sauvegardé:  {output_path}")


def main():
    """Fonction principale"""
    print("="*70)
    print("📊 LLM FIREWALL - ÉVALUATION COMPLÈTE")
    print("="*70)
    print()
    
    # 1. Initialiser le firewall
    firewall = LLMFirewall()
    
    # 2. Charger les données de test
    test_cases = load_test_data()
    print(f"📂 {len(test_cases)} cas de test chargés\n")
    
    # 3. Évaluer
    results, latencies = evaluate_firewall(firewall, test_cases)
    
    # 4. Calculer les métriques
    metrics = compute_metrics(results)
    
    # 5. Afficher les résultats
    print("\n" + "="*70)
    print("🎯 RÉSULTATS")
    print("="*70)
    print(f"Accuracy:   {metrics['accuracy']*100:.2f}%")
    print(f"Precision: {metrics['precision']*100:.2f}%")
    print(f"Recall:    {metrics['recall']*100:.2f}%")
    print(f"F1-Score:   {metrics['f1_score']*100:.2f}%")
    print(f"\nLatence moyenne: {sum(latencies)/len(latencies):.2f} ms")
    print("="*70)
    
    # 6. Générer le rapport
    generate_report(metrics, latencies, results)
    
    print("\n✅ Évaluation terminée!\n")


if __name__ == "__main__":
    main()