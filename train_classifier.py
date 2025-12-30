"""
Entraînement du modèle Deep Learning Classifier
Crée un MLP pour classification des menaces
"""

import json
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sentence_transformers import SentenceTransformer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import numpy as np
from pathlib import Path

# Import du modèle depuis firewall.py
from firewall import DLClassifier


class ThreatDataset(Dataset):
    """Dataset PyTorch pour les menaces"""
    def __init__(self, embeddings, labels):
        self.embeddings = torch.FloatTensor(embeddings)
        self.labels = torch.LongTensor(labels)
    
    def __len__(self):
        return len(self.labels)
    
    def __getitem__(self, idx):
        return self.embeddings[idx], self.labels[idx]


def load_and_prepare_data(dataset_path="data/threat_dataset.json"):
    """Charge et prépare les données"""
    print("📂 Chargement du dataset...")
    
    with open(dataset_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Créer les listes de textes et labels
    texts = []
    labels = []
    label_mapping = {
        'safe': 0,
        'jailbreak': 1,
        'prompt_injection': 2,
        'sensitive_leak': 3
    }
    
    for category, prompts in data. items():
        label = label_mapping.get(category, 0)
        for prompt in prompts:
            texts. append(prompt)
            labels. append(label)
    
    print(f"✅ {len(texts)} exemples chargés")
    print(f"   - Safe: {labels.count(0)}")
    print(f"   - Jailbreak: {labels.count(1)}")
    print(f"   - Injection: {labels.count(2)}")
    print(f"   - Sensitive:  {labels.count(3)}")
    
    return texts, labels, label_mapping


def generate_embeddings(texts, model_name='all-MiniLM-L6-v2'):
    """Génère les embeddings avec Sentence-BERT"""
    print(f"\n🧮 Génération des embeddings ({model_name})...")
    model = SentenceTransformer(model_name)
    embeddings = model.encode(texts, show_progress_bar=True, convert_to_numpy=True)
    print(f"✅ Embeddings générés:  {embeddings.shape}")
    return embeddings


def train_model(train_loader, val_loader, num_epochs=50):
    """Entraîne le modèle DL"""
    print("\n🤖 Entraînement du modèle Deep Learning...")
    
    # Initialisation
    model = DLClassifier(input_dim=384, hidden_dim=128, num_classes=4)
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    
    best_val_acc = 0.0
    
    for epoch in range(num_epochs):
        # Mode entraînement
        model.train()
        train_loss = 0.0
        correct = 0
        total = 0
        
        for embeddings, labels in train_loader: 
            optimizer.zero_grad()
            outputs = model(embeddings)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item()
            _, predicted = torch. max(outputs.data, 1)
            total += labels.size(0)
            correct += (predicted == labels).sum().item()
        
        train_acc = 100 * correct / total
        
        # Mode évaluation
        model.eval()
        val_correct = 0
        val_total = 0
        
        with torch.no_grad():
            for embeddings, labels in val_loader:
                outputs = model(embeddings)
                _, predicted = torch.max(outputs.data, 1)
                val_total += labels.size(0)
                val_correct += (predicted == labels).sum().item()
        
        val_acc = 100 * val_correct / val_total
        
        # Sauvegarde du meilleur modèle
        if val_acc > best_val_acc:
            best_val_acc = val_acc
            Path("models").mkdir(exist_ok=True)
            torch.save(model.state_dict(), "models/dl_classifier.pt")
        
        if (epoch + 1) % 10 == 0:
            print(f"Epoch [{epoch+1}/{num_epochs}] - Train Loss: {train_loss/len(train_loader):.4f} - Train Acc: {train_acc:.2f}% - Val Acc: {val_acc:.2f}%")
    
    print(f"\n✅ Entraînement terminé!  Meilleure validation accuracy: {best_val_acc:.2f}%")
    return model


def evaluate_model(model, test_loader, label_mapping):
    """Évalue le modèle sur le test set"""
    print("\n📊 Évaluation finale...")
    
    model.eval()
    all_preds = []
    all_labels = []
    
    with torch.no_grad():
        for embeddings, labels in test_loader:
            outputs = model(embeddings)
            _, predicted = torch.max(outputs.data, 1)
            all_preds.extend(predicted.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
    
    # Reverse mapping
    label_names = {v: k for k, v in label_mapping.items()}
    target_names = [label_names[i] for i in sorted(label_names.keys())]
    
    # Rapport de classification
    print("\n" + "="*70)
    print(classification_report(all_labels, all_preds, target_names=target_names))
    print("="*70)
    
    # Matrice de confusion
    cm = confusion_matrix(all_labels, all_preds)
    print("\n📈 Matrice de Confusion:")
    print(cm)


def main():
    """Fonction principale d'entraînement"""
    print("="*70)
    print("🔥 LLM FIREWALL - ENTRAÎNEMENT DU MODÈLE DL")
    print("="*70)
    
    # 1. Charger les données
    texts, labels, label_mapping = load_and_prepare_data()
    
    # 2. Générer les embeddings
    embeddings = generate_embeddings(texts)
    
    # 3. Split train/val/test
    X_train, X_temp, y_train, y_temp = train_test_split(
        embeddings, labels, test_size=0.3, random_state=42, stratify=labels
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
    )
    
    print(f"\n📊 Split des données:")
    print(f"   - Train: {len(X_train)}")
    print(f"   - Validation: {len(X_val)}")
    print(f"   - Test: {len(X_test)}")
    
    # 4. Créer les DataLoaders
    train_dataset = ThreatDataset(X_train, y_train)
    val_dataset = ThreatDataset(X_val, y_val)
    test_dataset = ThreatDataset(X_test, y_test)
    
    train_loader = DataLoader(train_dataset, batch_size=8, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=8, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=8, shuffle=False)
    
    # 5. Entraîner le modèle
    model = train_model(train_loader, val_loader, num_epochs=50)
    
    # 6. Évaluation finale
    evaluate_model(model, test_loader, label_mapping)
    
    print("\n✅ Modèle sauvegardé dans:  models/dl_classifier.pt")
    print("🚀 Vous pouvez maintenant utiliser le firewall avec le modèle DL!\n")


if __name__ == "__main__":
    main()