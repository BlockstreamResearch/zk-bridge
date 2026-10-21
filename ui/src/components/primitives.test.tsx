// Error text can quote an API, a wallet or a transaction, none of which the page controls: Linkified links only what
// links.ts linkAllowed allows, and leaves any other URL as text.
import { DEFAULTS } from '@bridge/core/config.js';
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { OPERATOR } from '../content/links';
import { Linkified } from './primitives';

const TX = 'ab'.repeat(32);

describe('Linkified', () => {
  it('links explorer and repository pages, without the punctuation after them', () => {
    const explorer = `${DEFAULTS.liquidExplorer}/tx/${TX}`;
    render(<Linkified text={`Burn not found; see ${explorer}. The guide is at ${OPERATOR}, step 3.`} />);
    const links = screen.getAllByRole('link');
    expect(links.map((a) => a.getAttribute('href'))).toEqual([explorer, OPERATOR]);
    for (const a of links) expect(a).toHaveAttribute('rel', 'noopener noreferrer');
  });

  it.each([
    ['another host', 'https://evil.example/claim-your-refund'],
    ['a look-alike host', 'https://blockstream.info.evil.example/liquidtestnet/tx/' + TX],
    ['the Liquid data API', `${DEFAULTS.esplora}/tx/${TX}/hex`],
    ['an explorer page with a query', `${DEFAULTS.liquidExplorer}/tx/${TX}?ref=x`],
    ['an explorer path out of its page', `${DEFAULTS.liquidExplorer}/tx/../../phish`],
    ['credentials', `https://user@sepolia.etherscan.io/tx/0x${TX}`],
  ])('leaves %s as plain text', (_, url) => {
    const { container } = render(<Linkified text={`The wallet said: open ${url} to continue`} />);
    expect(screen.queryByRole('link')).toBeNull();
    expect(container.querySelector('a')).toBeNull();
    expect(container).toHaveTextContent(`The wallet said: open ${url} to continue`);
  });

  it('links the allowed URL and not the disallowed one in the same text', () => {
    const explorer = `${DEFAULTS.ethExplorer}/tx/0x${TX}`;
    render(<Linkified text={`Sent ${explorer}; details at https://evil.example/x`} />);
    expect(screen.getAllByRole('link').map((a) => a.getAttribute('href'))).toEqual([explorer]);
  });
});
