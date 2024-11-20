# Release Process

This project uses GitHub Actions and GoReleaser for automated releases.

## Making a Release

1. Ensure all changes are committed and pushed:
```bash
git status
git push origin main
```

2. Create and push a tag:
```bash
# For a regular release
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

3. The GitHub Action will automatically:
   - Build binaries for all platforms
   - Create a GitHub release
   - Upload binaries
   - Generate changelog
   - Publish the release

4. Monitor the release:
   - Go to GitHub Actions tab to see the workflow progress
   - Check the releases page for the published release

## Version Tags

- Release: `v1.0.0`, `v2.1.0`, etc.


## Troubleshooting

If a release fails:
1. Check the Actions tab for error messages
2. Fix any issues
3. Delete the tag locally and remotely:
```bash
git tag -d <tag-name>
git push origin :refs/tags/<tag-name>
```
4. Create and push the tag again