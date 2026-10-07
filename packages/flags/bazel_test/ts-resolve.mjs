// Resolve hook for the Bazel contract test only. src/ uses extensionless
// relative imports (bundler resolution, as the pnpm workspace and consumers
// expect), which Node's ESM loader does not resolve. This retries a relative
// specifier that has no extension with ".ts". The shipped source is unchanged.
export async function resolve(specifier, context, nextResolve) {
	try {
		return await nextResolve(specifier, context);
	} catch (error) {
		const relative = specifier.startsWith('./') || specifier.startsWith('../');
		const last = specifier.slice(specifier.lastIndexOf('/') + 1);
		if (error?.code === 'ERR_MODULE_NOT_FOUND' && relative && !last.includes('.')) {
			return nextResolve(`${specifier}.ts`, context);
		}
		throw error;
	}
}
