# utils/pagination.py
"""
Reusable pagination helper for all list endpoints.
Prevents returning thousands of documents in a single response.
"""

from math import ceil
from flask import request
from bson import ObjectId
import datetime


def serialize_doc(doc):
    """
    Convert a MongoDB document to a JSON-serializable dict.
    Handles ObjectId, datetime, and nested structures.
    """
    if doc is None:
        return None

    if isinstance(doc, list):
        return [serialize_doc(item) for item in doc]

    if isinstance(doc, dict):
        result = {}
        for key, value in doc.items():
            if isinstance(value, ObjectId):
                result[key] = str(value)
            elif isinstance(value, datetime.datetime):
                result[key] = value.isoformat()
            elif isinstance(value, dict):
                result[key] = serialize_doc(value)
            elif isinstance(value, list):
                result[key] = serialize_doc(value)
            else:
                result[key] = value
        return result

    if isinstance(value, ObjectId):
        return str(doc)

    return doc


def paginate(collection, filter_query=None, sort_field="created_at", sort_dir=-1,
             max_per_page=100, default_per_page=20, serialize_fn=None):
    """
    Generic pagination for any MongoDB collection.

    Usage:
        return jsonify(paginate(db.targets, filter_query={"status": "active"}))

    Query params read from request automatically:
        ?page=1         → which page (default 1)
        ?per_page=20    → items per page (default 20, max 100)
        ?sort=field     → sort field (optional override)
        ?order=asc|desc → sort order (optional override)

    Returns:
        {
            "data": [...],
            "pagination": {
                "page": 1,
                "per_page": 20,
                "total": 150,
                "pages": 8,
                "has_next": True,
                "has_prev": False
            }
        }
    """
    if filter_query is None:
        filter_query = {}

    # Read pagination params from query string
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", default_per_page, type=int)

    # Sanitize
    page = max(1, page)  # Minimum page 1
    per_page = max(1, min(per_page, max_per_page))  # Clamp between 1 and max

    # Optional sort override from query params
    sort_override = request.args.get("sort", None)
    if sort_override:
        sort_field = sort_override

    order_param = request.args.get("order", None)
    if order_param == "asc":
        sort_dir = 1
    elif order_param == "desc":
        sort_dir = -1

    # Calculate skip
    skip = (page - 1) * per_page

    # Get total count for this filter
    total = collection.count_documents(filter_query)
    total_pages = ceil(total / per_page) if per_page > 0 else 0

    # Fetch the page of documents
    cursor = collection.find(filter_query)

    # Only sort if the sort field is likely to exist
    # (avoids errors on collections without created_at)
    try:
        cursor = cursor.sort(sort_field, sort_dir)
    except Exception:
        pass  # If sort fails, return unsorted

    cursor = cursor.skip(skip).limit(per_page)

    documents = list(cursor)

    # Serialize
    if serialize_fn:
        data = [serialize_fn(doc) for doc in documents]
    else:
        data = serialize_doc(documents)

    return {
        "data": data,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1
        }
    }