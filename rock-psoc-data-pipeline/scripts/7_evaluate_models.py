"""
Comprehensive Model Evaluation Script - ENHANCED VERSION
Script: 7_evaluate_models.py

Loads all trained models and generates detailed evaluation reports
Handles missing models gracefully and provides comprehensive visualizations
"""

import json
import os
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Set style
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 8)
plt.rcParams['font.size'] = 10

print("=" * 70)
print("COMPREHENSIVE MODEL EVALUATION")
print("=" * 70)

# ============================================
# 1. LOAD EVALUATION METRICS
# ============================================
print("\n[1/5] Loading evaluation metrics...")

metrics_files = {
    'Intrusion Detection': 'models/evaluation/intrusion_detection_metrics.json',
    'Phishing Detection': 'models/evaluation/phishing_detection_metrics.json',
    'Vulnerability Scoring': 'models/evaluation/vulnerability_scoring_metrics.json'
}

all_metrics = {}
tasks_found = []
tasks_missing = []

for task_name, filepath in metrics_files.items():
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f:
                all_metrics[task_name] = json.load(f)
            print(f"   ✅ Loaded: {task_name}")
            tasks_found.append(task_name)
        except Exception as e:
            print(f"   ⚠️  Error loading {task_name}: {str(e)[:50]}")
            tasks_missing.append(task_name)
    else:
        print(f"   ⚠️  Missing: {task_name}")
        tasks_missing.append(task_name)

if not all_metrics:
    print("\n❌ Error: No evaluation metrics found!")
    print("   Please run training scripts first (4, 5, 6)")
    exit(1)

print(f"\n   Found {len(tasks_found)} of {len(metrics_files)} tasks")

# ============================================
# 2. GENERATE COMPARISON TABLES
# ============================================
print("\n[2/5] Generating comparison tables...")

# Create evaluation directory for plots
os.makedirs('models/evaluation/plots', exist_ok=True)

# Initialize summary data
all_model_results = []

# ============================================
# INTRUSION DETECTION
# ============================================
if 'Intrusion Detection' in all_metrics:
    print("\n" + "=" * 70)
    print("INTRUSION DETECTION MODELS (NSL-KDD)")
    print("=" * 70)
    
    models_data = all_metrics['Intrusion Detection']['models']
    df_intrusion = pd.DataFrame(models_data).T
    df_intrusion = df_intrusion.sort_values('f1_score', ascending=False)
    
    print("\n" + df_intrusion.to_string())
    
    best_model = all_metrics['Intrusion Detection']['best_model']
    best_f1 = models_data[best_model]['f1_score']
    
    print(f"\n🏆 Best Model: {best_model} (F1: {best_f1:.4f})")
    print(f"   Classes: {len(all_metrics['Intrusion Detection']['class_names'])}")
    
    for model_name, metrics in models_data.items():
        all_model_results.append({
            'Task': 'Intrusion Detection',
            'Model': model_name,
            'Accuracy': metrics['accuracy'],
            'F1-Score': metrics['f1_score'],
            'Best': '🏆' if model_name == best_model else ''
        })

# ============================================
# PHISHING DETECTION
# ============================================
if 'Phishing Detection' in all_metrics:
    print("\n" + "=" * 70)
    print("PHISHING DETECTION MODELS")
    print("=" * 70)
    
    models_data = all_metrics['Phishing Detection']['models']
    df_phishing = pd.DataFrame(models_data).T
    
    if 'auc_roc' in df_phishing.columns:
        df_phishing = df_phishing.sort_values('auc_roc', ascending=False)
    else:
        df_phishing = df_phishing.sort_values('f1_score', ascending=False)
    
    print("\n" + df_phishing.to_string())
    
    best_model = all_metrics['Phishing Detection']['best_model']
    best_metrics = models_data[best_model]
    
    print(f"\n🏆 Best Model: {best_model}")
    if 'auc_roc' in best_metrics:
        print(f"   AUC-ROC: {best_metrics['auc_roc']:.4f}")
    
    for model_name, metrics in models_data.items():
        all_model_results.append({
            'Task': 'Phishing Detection',
            'Model': model_name,
            'Accuracy': metrics['accuracy'],
            'F1-Score': metrics['f1_score'],
            'AUC-ROC': metrics.get('auc_roc', 0),
            'Best': '🏆' if model_name == best_model else ''
        })

# ============================================
# VULNERABILITY SCORING
# ============================================
if 'Vulnerability Scoring' in all_metrics:
    print("\n" + "=" * 70)
    print("VULNERABILITY SCORING MODELS (CISA KEV)")
    print("=" * 70)
    
    print("\n📊 REGRESSION (Risk Score 0-100):")
    reg_data = all_metrics['Vulnerability Scoring']['regression']
    df_vuln_reg = pd.DataFrame(reg_data).T
    if 'mae' in df_vuln_reg.columns:
        df_vuln_reg = df_vuln_reg.sort_values('mae')
    print("\n" + df_vuln_reg.to_string())
    
    best_reg = all_metrics['Vulnerability Scoring']['best_regression_model']
    print(f"\n🏆 Best: {best_reg}")
    
    print("\n📊 CLASSIFICATION (Severity):")
    clf_data = all_metrics['Vulnerability Scoring']['classification']
    df_vuln_clf = pd.DataFrame(clf_data).T
    if 'f1_score' in df_vuln_clf.columns:
        df_vuln_clf = df_vuln_clf.sort_values('f1_score', ascending=False)
    print("\n" + df_vuln_clf.to_string())
    
    best_clf = all_metrics['Vulnerability Scoring']['best_classification_model']
    print(f"\n🏆 Best: {best_clf}")

# ============================================
# 3. CONFUSION MATRICES
# ============================================
print("\n[3/5] Generating confusion matrices...")

confusion_matrices = {
    'Intrusion Detection': 'models/evaluation/intrusion_detection_confusion_matrix.json',
    'Phishing Detection': 'models/evaluation/phishing_detection_confusion_matrix.json'
}

for task_name, filepath in confusion_matrices.items():
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f:
                cm_data = json.load(f)
            
            cm = np.array(cm_data['confusion_matrix'])
            class_names = cm_data['class_names']
            
            fig, ax = plt.subplots(figsize=(10, 8))
            sns.heatmap(cm, annot=True, fmt='d', cmap='YlOrRd',
                       xticklabels=class_names, yticklabels=class_names,
                       cbar_kws={'label': 'Count'}, ax=ax)
            
            ax.set_title(f'{task_name} - Confusion Matrix', fontsize=14, fontweight='bold')
            ax.set_ylabel('True Label')
            ax.set_xlabel('Predicted Label')
            
            if len(class_names) > 3:
                plt.xticks(rotation=45, ha='right')
            
            plt.tight_layout()
            plot_filename = f"models/evaluation/plots/{task_name.replace(' ', '_').lower()}_confusion_matrix.png"
            plt.savefig(plot_filename, dpi=300, bbox_inches='tight')
            plt.close()
            
            print(f"   ✅ Saved: {plot_filename}")
        except Exception as e:
            print(f"   ⚠️  Error: {str(e)[:50]}")

# ============================================
# 4. COMPARISON CHARTS
# ============================================
print("\n[4/5] Creating comparison charts...")

if all_model_results:
    try:
        df_results = pd.DataFrame(all_model_results)
        
        # Best models bar chart
        best_models = df_results[df_results['Best'] == '🏆']
        
        if len(best_models) > 0:
            fig, ax = plt.subplots(figsize=(10, 6))
            
            tasks = best_models['Task'].values
            models = best_models['Model'].values
            f1_scores = best_models['F1-Score'].values
            
            bars = ax.barh(range(len(tasks)), f1_scores, 
                          color=plt.cm.viridis(np.linspace(0.3, 0.9, len(tasks))))
            
            ax.set_yticks(range(len(tasks)))
            ax.set_yticklabels([f"{task}\n({model})" for task, model in zip(tasks, models)])
            ax.set_xlabel('F1-Score')
            ax.set_title('Best Model Performance by Task', fontweight='bold')
            ax.set_xlim(0, 1.0)
            ax.grid(axis='x', alpha=0.3)
            
            for i, (bar, score) in enumerate(zip(bars, f1_scores)):
                ax.text(score + 0.02, i, f'{score:.4f}', va='center', fontweight='bold')
            
            plt.tight_layout()
            plt.savefig('models/evaluation/plots/best_models_summary.png', dpi=300, bbox_inches='tight')
            plt.close()
            
            print("   ✅ Saved: best_models_summary.png")
    except Exception as e:
        print(f"   ⚠️  Error: {str(e)[:50]}")

# ============================================
# 5. MASTER REPORT
# ============================================
print("\n[5/5] Creating master report...")

best_models_summary = []

if 'Intrusion Detection' in all_metrics:
    best_model = all_metrics['Intrusion Detection']['best_model']
    best_models_summary.append({
        'Task': 'Network Intrusion Detection',
        'Best Model': best_model,
        'F1-Score': all_metrics['Intrusion Detection']['models'][best_model]['f1_score']
    })

if 'Phishing Detection' in all_metrics:
    best_model = all_metrics['Phishing Detection']['best_model']
    metrics = all_metrics['Phishing Detection']['models'][best_model]
    best_models_summary.append({
        'Task': 'Phishing URL Detection',
        'Best Model': best_model,
        'F1-Score': metrics['f1_score'],
        'AUC-ROC': metrics.get('auc_roc', 0)
    })

if 'Vulnerability Scoring' in all_metrics:
    best_reg = all_metrics['Vulnerability Scoring']['best_regression_model']
    best_clf = all_metrics['Vulnerability Scoring']['best_classification_model']
    
    best_models_summary.append({
        'Task': 'Vulnerability Risk Score',
        'Best Model': best_reg,
        'MAE': all_metrics['Vulnerability Scoring']['regression'][best_reg].get('mae', 0)
    })
    
    best_models_summary.append({
        'Task': 'Vulnerability Severity',
        'Best Model': best_clf,
        'F1-Score': all_metrics['Vulnerability Scoring']['classification'][best_clf].get('f1_score', 0)
    })

if best_models_summary:
    summary_df = pd.DataFrame(best_models_summary)
    print("\n" + "=" * 70)
    print("MASTER MODEL SUMMARY")
    print("=" * 70)
    print("\n" + summary_df.to_string(index=False))

# Save report
report_data = {
    'evaluation_date': datetime.now().isoformat(),
    'tasks_evaluated': len(all_metrics),
    'tasks_found': tasks_found,
    'tasks_missing': tasks_missing,
    'best_models_summary': best_models_summary,
    'detailed_metrics': all_metrics
}

with open('models/evaluation/master_evaluation_report.json', 'w') as f:
    json.dump(report_data, f, indent=4)

print("\n✅ Saved: master_evaluation_report.json")

if best_models_summary:
    summary_df.to_csv('models/evaluation/best_models_summary.csv', index=False)
    print("✅ Saved: best_models_summary.csv")

# ============================================
# SUMMARY
# ============================================
print("\n" + "=" * 70)
print("EVALUATION COMPLETE!")
print("=" * 70)

print(f"\n📊 Summary:")
print(f"   Tasks Evaluated: {len(tasks_found)}")
if tasks_missing:
    print(f"   Tasks Missing: {', '.join(tasks_missing)}")

plot_files = [f for f in os.listdir('models/evaluation/plots') if f.endswith('.png')] if os.path.exists('models/evaluation/plots') else []
print(f"   Plots Generated: {len(plot_files)}")

print(f"\n📁 Outputs:")
print(f"   models/evaluation/master_evaluation_report.json")
print(f"   models/evaluation/best_models_summary.csv")
print(f"   models/evaluation/plots/")

if best_models_summary:
    print(f"\n🏆 Best Models:")
    for item in best_models_summary:
        print(f"   {item['Task']:35} → {item['Best Model']}")

print(f"\n✅ Next: Run 8_upload_to_supabase.py")