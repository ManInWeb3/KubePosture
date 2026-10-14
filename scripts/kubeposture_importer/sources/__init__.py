"""Where the snapshot comes from: the live kube-api or a captured folder.

Both return `by_kind: dict[str, list[dict]]`. A kind that is ABSENT from
the dict means "this CRD is not installed / not captured" — the kind is
then left out of the import entirely. A kind mapped to `[]` means
"installed, currently no objects" — the importer ships an empty bundle
so the server's zero-input (scanner outage) rule can fire.
"""
