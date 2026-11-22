"""Extract product coordinates consistently for NVD catalog search and detail."""
from .offline_cpe import _fields


def cna_products(record):
    """Keep each NVD affectedData contributor separate from its products.

    The NVD 2.2 schema wraps CVE Program product records in
    ``affected: [{source, affectedData: [...]}]``. Older local imports may contain
    the bare CVE Program ``containers.cna.affected`` product list instead.
    """
    containers = record.get("containers") if isinstance(record.get("containers"), dict) else {}
    cna = containers.get("cna") if isinstance(containers.get("cna"), dict) else {}
    provider = cna.get("providerMetadata") if isinstance(cna.get("providerMetadata"), dict) else {}
    fallback_source = str(record.get("sourceIdentifier") or provider.get("shortName") or provider.get("orgId") or "출처 미제공")
    affected = record.get("affected")
    if affected is None:
        affected = cna.get("affected")
    if isinstance(affected, dict):
        affected = affected.get("products", affected.get("affected", [affected]))
    products = []
    for item in affected if isinstance(affected, list) else []:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("affectedData"), list):
            products.extend((product, str(item.get("source") or fallback_source)) for product in item["affectedData"] if isinstance(product, dict))
        elif any(field in item for field in ("vendor", "product", "packageName")):
            products.append((item, fallback_source))
    return products


def cpe_leaves(value, depth=0):
    if depth > 24:
        return
    if isinstance(value, list):
        for item in value:
            yield from cpe_leaves(item, depth + 1)
    elif isinstance(value, dict):
        if isinstance(value.get("criteria"), str):
            yield value
        for key in ("nodes", "children", "cpeMatch"):
            yield from cpe_leaves(value.get(key), depth + 1)


def cna_names(product):
    return (str(product.get("vendor") or "미제공"),
            str(product.get("product") or product.get("packageName") or "미제공"))


def searchable_names(record):
    for product, _ in cna_products(record):
        yield cna_names(product)
    for match in cpe_leaves(record.get("configurations")):
        if match.get("vulnerable") is not True:
            continue
        try:
            fields = _fields(match["criteria"])
        except (ValueError, KeyError):
            continue
        yield fields[1], fields[2]
