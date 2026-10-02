import logging
from fastapi import APIRouter, Query, Depends
from datetime import datetime, timedelta
from src.api.auth_guard import require_page, require_action

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/keyword-analysis", tags=["keyword-analysis"], dependencies=[Depends(require_page("Keyword Analysis"))])


@router.get("/overview")
def keyword_overview():
    from src.core.db import SessionLocal
    from src.models.schema import Keyword, Article

    session = SessionLocal()
    try:
        total_keywords = session.query(Keyword).count()
        total_articles = session.query(Article).count()
        keywords_list = session.query(Keyword.weight).all()

        if not keywords_list:
            return {
                "total_keywords": 0,
                "total_articles": 0,
                "avg_weight": 0,
                "max_weight": 0,
                "min_weight": 0,
                "keywords_used": 0,
                "keywords_unused": 0,
            }

        weights = [weight for (weight,) in keywords_list]
        used_words = set()
        articles_with_kw = 0
        for (keywords_found,) in session.query(Article.keywords_found).yield_per(1000):
            if keywords_found:
                kw_list = keywords_found if isinstance(keywords_found, list) else []
                if kw_list:
                    articles_with_kw += 1
                    for w in kw_list:
                        used_words.add(w.lower())

        return {
            "total_keywords": total_keywords,
            "total_articles": total_articles,
            "avg_weight": round(sum(weights) / len(weights), 1),
            "max_weight": max(weights),
            "min_weight": min(weights),
            "keywords_used": len(used_words),
            "keywords_unused": total_keywords - len(used_words),
            "articles_with_keywords": articles_with_kw,
            "articles_without_keywords": total_articles - articles_with_kw,
        }
    finally:
        session.close()


@router.get("/keyword-stats")
def keyword_stats(
    sort_by: str = Query("trigger_count", description="weight|trigger_count|avg_score_contribution"),
    order: str = Query("desc"),
    search: str = Query(""),
    limit: int = Query(100),
):
    from src.core.db import SessionLocal
    from src.models.schema import Keyword, Article
    from collections import defaultdict

    session = SessionLocal()
    try:
        keywords = session.query(Keyword).all()
        if search:
            keywords = [k for k in keywords if search.lower() in k.word.lower()]

        trigger_counts = defaultdict(int)
        score_contributions = defaultdict(list)

        for (keywords_found,) in session.query(Article.keywords_found).yield_per(1000):
            if keywords_found:
                kw_list = keywords_found if isinstance(keywords_found, list) else []
                for w in kw_list:
                    wl = w.lower()
                    trigger_counts[wl] += 1

        for kw in keywords:
            wl = kw.word.lower()
            if wl in trigger_counts:
                score_contributions[wl].append(kw.weight * trigger_counts[wl])

        results = []
        for kw in keywords:
            wl = kw.word.lower()
            tc = trigger_counts.get(wl, 0)
            avg_sc = round(sum(score_contributions[wl]) / len(score_contributions[wl]), 1) if score_contributions[wl] else 0
            results.append({
                "id": kw.id,
                "word": kw.word,
                "weight": kw.weight,
                "trigger_count": tc,
                "avg_score_contribution": avg_sc,
            })

        reverse = order == "desc"
        sort_keys = {
            "weight": lambda x: x["weight"],
            "trigger_count": lambda x: x["trigger_count"],
            "avg_score_contribution": lambda x: x["avg_score_contribution"],
        }
        key_fn = sort_keys.get(sort_by, sort_keys["trigger_count"])
        results.sort(key=key_fn, reverse=reverse)

        return results[:limit]
    finally:
        session.close()


@router.get("/category-distribution")
def category_distribution(
    days: int = Query(0, description="0=all time"),
):
    from src.core.db import SessionLocal
    from src.models.schema import Article
    from collections import Counter

    session = SessionLocal()
    try:
        query = session.query(Article)
        if days > 0:
            cutoff = datetime.utcnow() - timedelta(days=days)
            query = query.filter(Article.published_date >= cutoff)

        articles = query.with_entities(Article.category, Article.score).yield_per(1000)
        cat_counts = Counter()
        cat_score_sums = {}
        total_articles = 0

        for category, score in articles:
            total_articles += 1
            cat = category or "General"
            cat_counts[cat] += 1
            cat_score_sums[cat] = cat_score_sums.get(cat, 0) + (score or 0)

        results = []
        for cat, count in cat_counts.most_common():
            avg_score = round(cat_score_sums[cat] / count, 1) if count else 0
            results.append({
                "category": cat,
                "count": count,
                "avg_score": avg_score,
                "percent": round(count / total_articles * 100, 1) if total_articles else 0,
            })

        return results
    finally:
        session.close()


@router.get("/timeline")
def keyword_timeline(
    keyword: str = Query("", description="Filter by keyword"),
    days: int = Query(30),
    interval: str = Query("day", description="day|week"),
):
    from src.core.db import SessionLocal
    from src.models.schema import Article
    from collections import defaultdict
    from datetime import datetime

    session = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(days=days)
        articles = session.query(
            Article.published_date, Article.score, Article.keywords_found
        ).filter(Article.published_date >= cutoff).yield_per(1000)

        daily_data = defaultdict(lambda: {"total": 0, "matched": 0, "score_sum": 0})

        for published_date, score, keywords_found in articles:
            if not published_date:
                continue
            if interval == "week":
                day_key = published_date.strftime("%Y-W%U")
            else:
                day_key = published_date.strftime("%Y-%m-%d")

            daily_data[day_key]["total"] += 1
            daily_data[day_key]["score_sum"] += score or 0

            if keywords_found:
                kw_list = keywords_found if isinstance(keywords_found, list) else []
                if keyword:
                    if any(keyword.lower() == w.lower() for w in kw_list):
                        daily_data[day_key]["matched"] += 1
                else:
                    if kw_list:
                        daily_data[day_key]["matched"] += 1

        results = []
        for day_key in sorted(daily_data.keys()):
            d = daily_data[day_key]
            avg_score = round(d["score_sum"] / d["total"], 1) if d["total"] else 0
            results.append({
                "date": day_key,
                "total_articles": d["total"],
                "matched_articles": d["matched"],
                "match_rate": round(d["matched"] / d["total"] * 100, 1) if d["total"] else 0,
                "avg_score": avg_score,
            })

        return results
    finally:
        session.close()


@router.get("/keyword-articles")
def keyword_articles(
    keyword: str = Query(...),
    limit: int = Query(50),
):
    from src.core.db import SessionLocal
    from src.models.schema import Article

    session = SessionLocal()
    try:
        articles = session.query(
            Article.id, Article.title, Article.source, Article.category, Article.score,
            Article.published_date, Article.keywords_found,
        ).order_by(Article.published_date.desc()).yield_per(500)
        matched = []
        for article_id, title, source, category, score, published_date, keywords_found in articles:
            if not keywords_found:
                continue
            kw_list = keywords_found if isinstance(keywords_found, list) else []
            if any(keyword.lower() == w.lower() for w in kw_list):
                matched.append({
                    "id": article_id,
                    "title": title,
                    "source": source,
                    "category": category,
                    "score": score,
                    "published_date": published_date.isoformat() if published_date else None,
                    "keywords_found": kw_list,
                })
                if len(matched) >= limit:
                    break

        return matched
    finally:
        session.close()


@router.get("/score-distribution")
def score_distribution(
    days: int = Query(0),
    bucket_size: int = Query(10),
):
    from src.core.db import SessionLocal
    from src.models.schema import Article

    session = SessionLocal()
    try:
        query = session.query(Article)
        if days > 0:
            cutoff = datetime.utcnow() - timedelta(days=days)
            query = query.filter(Article.published_date >= cutoff)

        articles = query.with_entities(Article.score, Article.category).yield_per(1000)
        buckets = {}
        for i in range(0, 101, bucket_size):
            label = f"{i}-{min(i + bucket_size - 1, 100)}"
            buckets[label] = {"count": 0, "categories": {}}

        for article_score, category in articles:
            score = int(article_score or 0)
            bucket_idx = min(score // bucket_size * bucket_size, 100 - bucket_size)
            label = f"{bucket_idx}-{min(bucket_idx + bucket_size - 1, 100)}"
            if label in buckets:
                buckets[label]["count"] += 1
                cat = category or "General"
                buckets[label]["categories"][cat] = buckets[label]["categories"].get(cat, 0) + 1

        results = []
        for label, data in buckets.items():
            top_cat = max(data["categories"].items(), key=lambda x: x[1])[0] if data["categories"] else "N/A"
            results.append({
                "bucket": label,
                "count": data["count"],
                "top_category": top_cat,
            })

        return results
    finally:
        session.close()


@router.get("/category-keyword-matrix")
def category_keyword_matrix(
    top_n: int = Query(20),
):
    from src.core.db import SessionLocal
    from src.models.schema import Article, Keyword
    from collections import defaultdict, Counter

    session = SessionLocal()
    try:
        keywords = {k.word.lower(): k.weight for k in session.query(Keyword).all()}
        articles = session.query(Article.category, Article.keywords_found).yield_per(1000)

        cat_kw_counts = defaultdict(Counter)
        for category, keywords_found in articles:
            if not keywords_found:
                continue
            cat = category or "General"
            kw_list = keywords_found if isinstance(keywords_found, list) else []
            for w in kw_list:
                cat_kw_counts[cat][w.lower()] += 1

        categories = sorted(cat_kw_counts.keys())
        all_kws = Counter()
        for counter in cat_kw_counts.values():
            all_kws.update(counter)

        top_keywords = [w for w, _ in all_kws.most_common(top_n)]

        matrix = []
        for cat in categories:
            row = {"category": cat}
            for kw in top_keywords:
                row[kw] = cat_kw_counts[cat].get(kw, 0)
            row["total"] = sum(cat_kw_counts[cat].values())
            matrix.append(row)

        return {"categories": categories, "keywords": top_keywords, "matrix": matrix}
    finally:
        session.close()


@router.get("/category-details")
def category_details(
    category: str = Query(...),
    days: int = Query(0),
):
    from src.core.db import SessionLocal
    from src.models.schema import Article
    from collections import Counter

    session = SessionLocal()
    try:
        query = session.query(Article).filter(Article.category == category)
        if days > 0:
            cutoff = datetime.utcnow() - timedelta(days=days)
            query = query.filter(Article.published_date >= cutoff)

        articles = query.with_entities(
            Article.id, Article.title, Article.source, Article.score,
            Article.published_date, Article.keywords_found,
        ).order_by(Article.published_date.desc()).limit(200).all()

        kw_counter = Counter()
        source_counter = Counter()
        scores = []
        for _article_id, _title, source, score, _published_date, keywords_found in articles:
            scores.append(score or 0)
            source_counter[source or "Unknown"] += 1
            if keywords_found:
                kw_list = keywords_found if isinstance(keywords_found, list) else []
                for w in kw_list:
                    kw_counter[w.lower()] += 1

        return {
            "category": category,
            "total_articles": len(articles),
            "avg_score": round(sum(scores) / len(scores), 1) if scores else 0,
            "top_keywords": [{"word": w, "count": c} for w, c in kw_counter.most_common(15)],
            "top_sources": [{"source": s, "count": c} for s, c in source_counter.most_common(10)],
            "recent_articles": [{
                "id": article_id,
                "title": title,
                "source": source,
                "score": score,
                "published_date": published_date.isoformat() if published_date else None,
                "keywords_found": keywords_found if isinstance(keywords_found, list) else [],
            } for article_id, title, source, score, published_date, keywords_found in articles[:50]],
        }
    finally:
        session.close()


@router.post("/recategorize", dependencies=[Depends(require_action("Action: Trigger AI Functions"))])
def recategorize_all():
    from src.core.db import SessionLocal
    from src.models.schema import Article
    from src.services.categorizer import categorize_text

    session = SessionLocal()
    try:
        total = 0
        changed = 0
        last_id = 0
        batch_size = 250
        while True:
            articles = session.query(
                Article.id, Article.title, Article.summary, Article.category
            ).filter(Article.id > last_id).order_by(Article.id).limit(batch_size).all()
            if not articles:
                break

            updates = []
            for article_id, title, summary, current_category in articles:
                new_category = categorize_text(f"{title or ''} {summary or ''}")
                if current_category != new_category:
                    updates.append({"id": article_id, "category": new_category})
            if updates:
                session.bulk_update_mappings(Article, updates)
                session.commit()
                changed += len(updates)

            total += len(articles)
            last_id = articles[-1][0]

        return {"status": "ok", "total": total, "changed": changed}
    finally:
        session.close()
