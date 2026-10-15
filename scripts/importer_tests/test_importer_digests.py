import pytest
from kubeposture_importer.digests import digest_from_image_id, digest_from_ref, normalize_digest

HEX = "a" * 64
SHA = f"sha256:{HEX}"


@pytest.mark.parametrize(
    "image_id",
    [
        f"registry.x/app@{SHA}",
        f"docker-pullable://registry.x/app@{SHA}",
        f"docker.io/library/nginx@{SHA}",
        SHA,
        f"SHA256:{HEX.upper()}",
    ],
)
def test_digest_from_image_id_accepts_every_runtime_form(image_id):
    assert digest_from_image_id(image_id) == SHA


@pytest.mark.parametrize(
    "image_id",
    ["", "docker://registry.x/app", "sha256:short", f"registry.x/app@sha512:{HEX}",
     f"registry.x/app@sha256:{'g' * 64}", "registry.x/app:1.2.3"],
)
def test_digest_from_image_id_rejects_garbage(image_id):
    assert digest_from_image_id(image_id) == ""


def test_digest_from_ref_only_counts_a_sha256_pin():
    assert digest_from_ref(f"registry.x/app:1@{SHA}") == SHA
    assert digest_from_ref(f"registry.x/app@{SHA}") == SHA
    assert digest_from_ref("registry.x/app:1") == ""
    assert digest_from_ref("") == ""
    assert digest_from_ref(f"registry.x/app@sha512:{HEX}") == ""


def test_normalize_digest_lowercases_and_validates_length():
    assert normalize_digest(f"  SHA256:{HEX.upper()} ") == SHA
    assert normalize_digest(f"sha256:{HEX[:-1]}") == ""
    assert normalize_digest(HEX) == "", "a bare hex string without the algorithm prefix is not accepted"
