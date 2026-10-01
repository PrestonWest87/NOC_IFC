from fastapi import APIRouter, Depends

from src.api.auth_guard import get_current_user
from src.core.permissions import public_permission_catalog

router = APIRouter(prefix="/api/v1/permissions", tags=["permissions"])


@router.get("/catalog")
def permission_catalog(_user=Depends(get_current_user)):
    """Expose the canonical permission descriptions to authenticated role editors."""
    return public_permission_catalog()
