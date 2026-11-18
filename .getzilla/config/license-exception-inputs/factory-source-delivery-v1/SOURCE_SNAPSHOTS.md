# Readable upstream source snapshots

`vendor/` holds every regular file from the two exact official source releases. These are corresponding-source DATA, never imported or executed by Getzilla. All115 files are UTF-8; original bytes and executable modes are preserved. Each closed `*-snapshot.json` binds all paths, original paths, sizes, SHA256 values and modes to the historical official archive and exact official index digest. Original gzip containers remain in ignored review evidence, not tracked source.

The Factory builder verifies complete selected snapshot membership without following links, checks each byte/hash/mode, and creates deterministic tar/gzip containers. Those containers are canonical repacks of unchanged source content. They are not the original publisher archives. `legal/source-map.json` records both the historical publisher archive identity and the actual delivered repacked container identity. Original wheel notices and full license texts remain separate and unchanged.

No license policy grant, binary-risk bypass, source-authenticity/reproducible-build claim, or waiver of other LGPL/vendor conditions is provided by this data directory.
