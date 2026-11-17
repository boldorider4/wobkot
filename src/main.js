function send_log(text) {
  try {
    fetch('/log', { method: 'POST', body: text, keepalive: true }).catch(() => {});
  } catch (e) {}
}

const logger = {
  verbose: true, // enable for debug logs

  init() {
    this.console = document.getElementById('console');
  },
  info(msg) {
    this.log('[+]', `${msg}`);
  },
  error(msg) {
    this.log('[-]', `${msg}`);
  },
  debug(msg) {
    if (this.verbose) this.log('[*]', `${msg}`);
  },
  log(prefix, msg) {
    const line = `${prefix} ${String(msg).replace(/\n/g, `\n${prefix} `)}\n`;

    if (this.console) {
      this.console.append(line);
      this.console.scrollTop = this.console.scrollHeight;
    }

    if (prefix !== '[*]') send_log(line);
  },
};

window.onerror = function (message, source, line, column, error) {
  let msg = message;

  if (error && error.stack) {
    msg += `\n${error.stack}`;
  } else {
    msg += `\n@${source}:${line}:${column}`;
  }

  logger.error(msg);
  return true;
};

window.onunhandledrejection = function (event) {
  const err = event.reason;

  let msg = err && err.message ? err.message : String(err);

  if (err && err.stack) {
    msg += `\n${err.stack}`;
  }

  logger.error(msg);
};

function load_script(src) {
  return new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = src;
    script.onload = resolve;
    script.onerror = () => {
      reject(new Error(`Failed to load script: ${src}`));
    };
    document.head.appendChild(script);
  });
}

async function load_file(src) {
  const res = await fetch(src);

  if (!res.ok) {
    throw new Error(`HTTP ${res.status}: ${src}`);
  }

  const buf = await res.arrayBuffer();
  return new Uint8Array(buf);
}

async function main() {
  logger.info('main() start');

  await load_script('src/misc.js');

  version.init();
  logger.info(`console=${version.console} firmware=${version}`);

  switch (version.console) {
    case 4:
      logger.info('loading src/ps4/impl.js');
      await load_script('src/ps4/impl.js');
      break;
    case 5:
      logger.info('loading src/ps5/impl.js');
      await load_script('src/ps5/impl.js');
      break;
    default:
      throw new Error(`Unsupported console ${version.console}`);
  }

  logger.info('loading src/userland.js');
  await load_script('src/userland.js');

  logger.info('running userland_main()');
  await userland_main();
  logger.info('userland done');

  logger.info('loading src/kernel.js');
  await load_script('src/kernel.js');

  logger.info('running kernel_main()');
  await kernel_main();
  logger.info('kernel done');
}

logger.init();
main();
