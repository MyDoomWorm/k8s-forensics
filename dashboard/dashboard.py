import streamlit as st
import sqlite3
import json
import sys
import os
import time
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'agent'))
from crypto_core import DB_PATH
from shredder import verify_chain_with_shredding as verify_chain

st.set_page_config(
    page_title="K8s Forensics Dashboard",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 Kubernetes Forensics — Verification Dashboard")
st.caption("Криптографическая верификация целостности доказательств | ML-DSA-65 (Dilithium)")

def load_evidence():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(
        "SELECT evidence_id, timestamp, event_type, data_hash, prev_hash, shred_status FROM evidence ORDER BY id DESC",
        conn
    )
    conn.close()
    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
    return df

def get_stats(df, chain_results):
    total = len(chain_results)
    valid = sum(1 for r in chain_results if r.get('status') == 'valid')
    tampered = sum(1 for r in chain_results if r.get('status') == 'TAMPERED')
    shredded = sum(1 for r in chain_results if r.get('status') == 'shredded')
    return total, valid, tampered, shredded

with st.sidebar:
    st.header("⚙️ Управление")
    auto_refresh = st.checkbox("Авто-обновление (30с)", value=False)
    if st.button("🔄 Обновить сейчас", use_container_width=True):
        st.rerun()
    st.divider()
    st.header("📊 Фильтры")
    event_filter = st.multiselect(
        "Тип события",
        ["pod_metadata", "k8s_event", "pod_logs", "test"],
        default=[]
    )
    st.divider()
    st.info("База данных:\n`" + DB_PATH + "`")

try:
    df = load_evidence()
    chain_results = verify_chain()
    total, valid, tampered, shredded = get_stats(df, chain_results)
except Exception as e:
    st.error(f"Ошибка загрузки данных: {e}")
    st.stop()

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("📦 Всего доказательств", total)
with col2:
    st.metric("✅ Валидных", valid, delta=None)
with col3:
    if tampered > 0:
        st.metric("🚨 Нарушений", tampered, delta=f"+{tampered}", delta_color="inverse")
    else:
        st.metric("🚨 Нарушений", 0)
with col4:
    st.metric("🗑️ Уничтожено", shredded)


st.divider()
if tampered == 0:
    st.success(f"✅ Цепь доверия intact — все {valid} доказательств прошли верификацию ML-DSA-65")
else:
    st.error(f"🚨 ОБНАРУЖЕНЫ НАРУШЕНИЯ ЦЕЛОСТНОСТИ: {tampered} доказательств скомпрометированы")

tab1, tab2, tab3 = st.tabs(["📋 Доказательства", "🔗 Верификация цепи", "📈 Статистика"])

with tab1:
    st.subheader("Собранные доказательства")
    display_df = df.copy()
    if event_filter:
        display_df = display_df[display_df['event_type'].isin(event_filter)]

    display_df['shred_status'] = display_df['shred_status'].map(
        {'active': '✅ active', 'shredded': '🗑️ shredded'}
    ).fillna('✅ active')
    display_df['data_hash'] = display_df['data_hash'].str[:16] + '...'
    display_df['prev_hash'] = display_df['prev_hash'].apply(
        lambda x: x[:16] + '...' if x != 'GENESIS' else '🔰 GENESIS'
    )
    display_df.columns = ['ID доказательства', 'Время', 'Тип события', 'Хеш данных', 'Хеш предыдущего', 'Статус']
    st.dataframe(display_df, use_container_width=True, height=400)

with tab2:
    st.subheader("Верификация криптографической цепи")
    chain_df = pd.DataFrame(chain_results)
    if not chain_df.empty:
        def status_icon(row):
            if row.get('status') == 'TAMPERED':
                return '🚨 TAMPERED'
            elif row.get('status') == 'shredded':
                return '🗑️ shredded'
            else:
                return '✅ valid'

        chain_df['Статус'] = chain_df.apply(status_icon, axis=1)
        chain_df['hash_ok'] = chain_df.get('hash_ok', pd.Series([None]*len(chain_df))).map(
            {True: '✅', False: '❌', None: '—'}
        )
        chain_df['chain_ok'] = chain_df.get('chain_ok', pd.Series([None]*len(chain_df))).map(
            {True: '✅', False: '❌', None: '—'}
        )
        chain_df['signature_ok'] = chain_df.get('signature_ok', pd.Series([None]*len(chain_df))).map(
            {True: '✅', False: '❌', None: '—'}
        )
        display_chain = chain_df[['evidence_id', 'Статус', 'hash_ok', 'chain_ok', 'signature_ok']].copy()
        display_chain.columns = ['ID доказательства', 'Статус', 'Хеш', 'Цепь', 'Подпись ML-DSA-65']
        st.dataframe(display_chain, use_container_width=True, height=400)

with tab3:
    st.subheader("Статистика по типам событий")
    if not df.empty:
        type_counts = df['event_type'].value_counts().reset_index()
        type_counts.columns = ['Тип события', 'Количество']
        col1, col2 = st.columns(2)
        with col1:
            st.dataframe(type_counts, use_container_width=True)
        with col2:
            st.bar_chart(type_counts.set_index('Тип события'))

        st.subheader("Временная шкала сбора")
        timeline_df = df.copy()
        timeline_df['count'] = 1
        timeline_df = timeline_df.set_index('timestamp').resample('1min')['count'].sum().reset_index()
        timeline_df.columns = ['Время', 'Артефактов']
        st.line_chart(timeline_df.set_index('Время'))

if auto_refresh:
    time.sleep(30)
    st.rerun()

