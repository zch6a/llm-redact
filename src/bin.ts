#!/usr/bin/env node
import { main } from './cli.ts';

process.stdout.on('error', (err: NodeJS.ErrnoException) => {
  if (err.code === 'EPIPE') process.exit(0);
});

process.exitCode = await main(process.argv.slice(2));
