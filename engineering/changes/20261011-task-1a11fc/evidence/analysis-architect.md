# architect analysis

Source: 05f85f12b72b3a897c45c24e172fac8317120b7c. Route: 1a11fc0a8f4b.

The shared child-test boundary is the smallest correct repair. Parent scope selection precedes dispatch and reads its own environment, so filtering a copied dictionary preserves full scope. No architecture authority or API change is needed. Explicit test-owned overrides remain possible. No code changed; read-only assessment.
