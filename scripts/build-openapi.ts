import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { openApiDocument } from '../server/openapi';

/** Writes docs/openapi.json from server/openapi.ts. `npm run build:openapi`. A test fails if the file is out of date. */
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const OPENAPI_FILE = path.join(root, 'docs', 'openapi.json');
fs.writeFileSync(OPENAPI_FILE, `${JSON.stringify(openApiDocument, null, 2)}\n`);
console.log(`written to ${path.relative(root, OPENAPI_FILE)}`);
