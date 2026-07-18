"""Security regression tests for the memory.json importer.

The entity ``name``/``entityType`` come straight from an untrusted memory.json
(the threat model designates imported files as hostile, and the same importer is
reachable over the HTTP import endpoint). They become filesystem path segments,
so a name like ``../../../evil`` must not escape the project root.
"""

import pytest

from basic_memory.importers.memory_json_importer import MemoryJsonImporter
from basic_memory.markdown.entity_parser import EntityParser
from basic_memory.markdown.markdown_processor import MarkdownProcessor
from basic_memory.services.file_service import FileService


@pytest.fixture
def memory_json_importer(tmp_path):
    """Build a MemoryJsonImporter rooted at an isolated project directory."""
    project = tmp_path / "project"
    project.mkdir()
    entity_parser = EntityParser(base_path=project)
    markdown_processor = MarkdownProcessor(entity_parser=entity_parser)
    file_service = FileService(base_path=project, markdown_processor=markdown_processor)
    return MemoryJsonImporter(project, markdown_processor, file_service), project


@pytest.mark.asyncio
async def test_memory_json_import_neutralizes_path_traversal(memory_json_importer, tmp_path):
    """A hostile entity name with '..' segments cannot write outside the project."""
    importer, project = memory_json_importer
    hostile = [
        {
            "type": "entity",
            "entityType": "../../../../etc",
            "name": "../../../../evil",
            "observations": ["x"],
        }
    ]

    result = await importer.import_data(hostile, destination_folder="")

    assert result.success
    # Nothing escaped the project root.
    assert not (tmp_path / "evil.md").exists()
    assert not (tmp_path / "etc").exists()
    # The note was written, and every written file stays inside the project.
    written = list(project.rglob("*.md"))
    assert written, "expected the note to be written inside the project"
    for path in written:
        assert path.resolve().is_relative_to(project.resolve())


@pytest.mark.asyncio
async def test_memory_json_import_writes_sanitized_normal_entity(memory_json_importer):
    """A normal entity still imports cleanly after sanitization."""
    importer, project = memory_json_importer
    entities = [
        {
            "type": "entity",
            "entityType": "note",
            "name": "meeting-notes",
            "observations": ["decided X"],
        }
    ]

    result = await importer.import_data(entities, destination_folder="")

    assert result.success
    assert result.entities == 1
    # clean_filename replaces hyphens with underscores (matching sibling importers).
    assert (project / "note" / "meeting_notes.md").exists()


@pytest.mark.asyncio
async def test_memory_json_import_handles_numeric_id_name(memory_json_importer):
    """A numeric `id` fallback name must not crash sanitization (it is str-coerced)."""
    importer, project = memory_json_importer
    entities = [
        {
            "type": "entity",
            "entityType": "note",
            "id": 123,  # numeric id used as the fallback name
            "observations": ["x"],
        }
    ]

    result = await importer.import_data(entities, destination_folder="")

    assert result.success
    assert result.entities == 1
    assert (project / "note" / "123.md").exists()
