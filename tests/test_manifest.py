import pytest

from desk.manifest import InputError, parse_manifest


def test_names_versions_comments_and_pep440():
    result = parse_manifest('# comment\nMy_Package.Name==v1.0  # pinned\nrequests==2.32.4\n')
    assert result['packages'][0] == {'name': 'my-package-name', 'version':'1.0', 'line':2}
    assert result['complete_manifest'] is True


@pytest.mark.parametrize('line', [
    'requests>=2', 'requests==2.*', 'requests[socks]==2.32.4',
    'requests==2.32.4; python_version>"3.9"', '-r /etc/passwd',
    '--index-url https://evil.example', '-e .',
    'pkg @ https://evil.example/package.whl', '$(touch hacked)==1',
    'pkg==1.0+local', 'pkg==not-a-version', 'pkg==1.0 --hash=sha256:123',
    'pkg==1.0\x00', 'pkg===1.0', '<script>alert(1)</script>',
])
def test_unsupported_lines_preserved_without_execution(line, tmp_path):
    result = parse_manifest(line)
    assert not result['packages']
    assert len(result['unsupported']) == 1
    assert result['complete_manifest'] is False
    assert not (tmp_path / 'hacked').exists()


def test_duplicate_and_conflicting_pins_are_coverage_gaps():
    result = parse_manifest('Foo_Bar==1.0\nfoo-bar==1.0\nfoo.bar==2.0')
    assert len(result['packages']) == 1
    assert [r['reason'] for r in result['unsupported']] == [
        'Duplicate package pin.', 'Conflicting versions for the same package.']


@pytest.mark.parametrize('value', ['', '  ', '# no pins', None, 12, [], 'x'*32769,
    '\n'.join('# comment' for _ in range(151)), '\n'.join(f'pkg{i}==1' for i in range(31))])
def test_manifest_limits(value):
    with pytest.raises(InputError):
        parse_manifest(value)


def test_exact_package_limit_and_utf8_byte_limit():
    assert len(parse_manifest('\n'.join(f'pkg{i}==1' for i in range(30)))['packages']) == 30
    with pytest.raises(InputError):
        parse_manifest('क' * 11000)
