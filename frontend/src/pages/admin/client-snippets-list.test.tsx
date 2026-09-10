// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { ClientSnippetsList } from './ClientSnippetsList'

describe('ClientSnippetsList', () => {
  it('renders all six framework snippets with real values (secret known)', () => {
    render(<ClientSnippetsList clientId="cid-1" clientSecret="plain-secret" secretKnown />)
    expect(screen.getByTestId('client-snippets')).toBeInTheDocument()
    for (const fw of ['nextjs', 'react', 'python', 'node', 'go', 'dotnet']) {
      expect(screen.getByTestId(`snippet-${fw}`)).toBeInTheDocument()
    }
    const reactBlock = screen.getByTestId('snippet-react')
    expect(within(reactBlock).getByText(/VITE_AUTHGLOW_CLIENT_ID=cid-1/)).toBeInTheDocument()
    // No secret banner when the secret is known
    expect(screen.queryByRole('note')).not.toBeInTheDocument()
  })

  it('shows placeholder secret + banner when the secret is unknown (edit mode)', () => {
    render(
      <ClientSnippetsList
        clientId="cid-9"
        clientSecret="<YOUR_CLIENT_SECRET>"
        secretKnown={false}
        startCollapsed
      />,
    )
    expect(screen.getByRole('note')).toBeInTheDocument()
    const nodeBlock = screen.getByTestId('snippet-node')
    expect(within(nodeBlock).getByText(/<YOUR_CLIENT_SECRET>/)).toBeInTheDocument()
    expect(within(nodeBlock).getByText(/AUTHGLOW_CLIENT_ID=cid-9/)).toBeInTheDocument()
  })
})
