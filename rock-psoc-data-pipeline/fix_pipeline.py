from pathlib import Path

f = Path('scripts/AUTOMATE_ML_PIPELINE.py')
content = f.read_text(encoding='utf-8')
content = content.replace(
    "help='Quick mode (50% data, faster training)'",
    "help='Quick mode (50pct data, faster training)'"
)
f.write_text(content, encoding='utf-8')
print('Fixed!')