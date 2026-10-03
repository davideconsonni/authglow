// @vitest-environment jsdom
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'

import { Button } from './button'
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from './card'
import { Input } from './input'
import {
  Table,
  TableHeader,
  TableBody,
  TableFooter,
  TableRow,
  TableHead,
  TableCell,
  TableCaption,
} from './table'
import { Tabs, TabsList, TabsTrigger, TabsContent } from './tabs'
import {
  Dialog,
  DialogTrigger,
  DialogContent,
  DialogHeader,
  DialogFooter,
  DialogTitle,
  DialogDescription,
  DialogClose,
} from './dialog'
import { Popover, PopoverTrigger, PopoverContent } from './popover'
import { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider } from './tooltip'
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuCheckboxItem,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuShortcut,
  DropdownMenuSub,
  DropdownMenuSubTrigger,
  DropdownMenuSubContent,
} from './dropdown-menu'
import {
  Drawer,
  DrawerTrigger,
  DrawerContent,
  DrawerHeader,
  DrawerFooter,
  DrawerTitle,
  DrawerDescription,
} from './drawer'
import {
  Command,
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
  CommandSeparator,
  CommandShortcut,
} from './command'

// Radix/vaul overlay primitives rely on browser APIs jsdom does not implement.
vi.stubGlobal(
  'ResizeObserver',
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  },
)
Element.prototype.scrollIntoView = vi.fn()
Element.prototype.hasPointerCapture = vi.fn(() => false)
Element.prototype.setPointerCapture = vi.fn()
Element.prototype.releasePointerCapture = vi.fn()

describe('ui/button', () => {
  it('renders every variant and forwards clicks', () => {
    const onClick = vi.fn()
    render(
      <div>
        <Button onClick={onClick}>Default</Button>
        <Button variant="destructive">Destructive</Button>
        <Button variant="outline" size="sm">
          Outline
        </Button>
        <Button variant="secondary" size="lg">
          Secondary
        </Button>
        <Button variant="ghost" size="icon" aria-label="ghost">
          G
        </Button>
        <Button variant="link">Link</Button>
        <Button asChild>
          <a href="#x">Anchor</a>
        </Button>
      </div>,
    )
    fireEvent.click(screen.getByText('Default'))
    expect(onClick).toHaveBeenCalledTimes(1)
    expect(screen.getByText('Anchor').tagName).toBe('A')
    expect(screen.getByLabelText('ghost')).toBeInTheDocument()
  })
})

describe('ui/card', () => {
  it('renders the whole card family', () => {
    render(
      <Card>
        <CardHeader>
          <CardTitle>Title</CardTitle>
          <CardDescription>Description</CardDescription>
        </CardHeader>
        <CardContent>Content</CardContent>
        <CardFooter>Footer</CardFooter>
      </Card>,
    )
    expect(screen.getByText('Title')).toBeInTheDocument()
    expect(screen.getByText('Description')).toBeInTheDocument()
    expect(screen.getByText('Content')).toBeInTheDocument()
    expect(screen.getByText('Footer')).toBeInTheDocument()
  })
})

describe('ui/input', () => {
  it('renders and emits changes', () => {
    const onChange = vi.fn()
    render(<Input placeholder="name" onChange={onChange} />)
    fireEvent.change(screen.getByPlaceholderText('name'), { target: { value: 'abc' } })
    expect(onChange).toHaveBeenCalled()
  })
})

describe('ui/table', () => {
  it('renders the whole table family', () => {
    render(
      <Table>
        <TableCaption>Caption</TableCaption>
        <TableHeader>
          <TableRow>
            <TableHead>Head</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow>
            <TableCell>Body</TableCell>
          </TableRow>
        </TableBody>
        <TableFooter>
          <TableRow>
            <TableCell>Footer</TableCell>
          </TableRow>
        </TableFooter>
      </Table>,
    )
    expect(screen.getByText('Caption')).toBeInTheDocument()
    expect(screen.getByText('Head')).toBeInTheDocument()
    expect(screen.getByText('Body')).toBeInTheDocument()
    expect(screen.getByText('Footer')).toBeInTheDocument()
  })
})

describe('ui/tabs', () => {
  it('switches the visible panel', () => {
    render(
      <Tabs defaultValue="a">
        <TabsList>
          <TabsTrigger value="a">Tab A</TabsTrigger>
          <TabsTrigger value="b">Tab B</TabsTrigger>
        </TabsList>
        <TabsContent value="a">Panel A</TabsContent>
        <TabsContent value="b">Panel B</TabsContent>
      </Tabs>,
    )
    expect(screen.getByText('Panel A')).toBeInTheDocument()
    fireEvent.mouseDown(screen.getByRole('tab', { name: 'Tab B' }))
    expect(screen.getByText('Panel B')).toBeInTheDocument()
  })
})

describe('ui/dialog', () => {
  it('renders an open dialog with header, footer and close', () => {
    render(
      <Dialog open>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Title</DialogTitle>
            <DialogDescription>Description</DialogDescription>
          </DialogHeader>
          <DialogFooter>Footer</DialogFooter>
          <DialogClose>Close me</DialogClose>
        </DialogContent>
      </Dialog>,
    )
    expect(screen.getByText('Title')).toBeInTheDocument()
    expect(screen.getByText('Description')).toBeInTheDocument()
    expect(screen.getByText('Footer')).toBeInTheDocument()
    expect(screen.getByText('Close me')).toBeInTheDocument()
  })

  it('opens from its trigger', () => {
    render(
      <Dialog>
        <DialogTrigger>Open</DialogTrigger>
        <DialogContent>
          <DialogTitle>Triggered</DialogTitle>
        </DialogContent>
      </Dialog>,
    )
    fireEvent.click(screen.getByText('Open'))
    expect(screen.getByText('Triggered')).toBeInTheDocument()
  })
})

describe('ui/popover', () => {
  it('renders the trigger and content', () => {
    render(
      <Popover open>
        <PopoverTrigger>Open popover</PopoverTrigger>
        <PopoverContent>Popover content</PopoverContent>
      </Popover>,
    )
    expect(screen.getByText('Popover content')).toBeInTheDocument()
  })
})

describe('ui/tooltip', () => {
  it('renders the trigger and content', () => {
    render(
      <TooltipProvider>
        <Tooltip open>
          <TooltipTrigger>Hover</TooltipTrigger>
          <TooltipContent>Tip content</TooltipContent>
        </Tooltip>
      </TooltipProvider>,
    )
    expect(screen.getByText('Tip content')).toBeInTheDocument()
  })
})

describe('ui/dropdown-menu', () => {
  it('renders an open menu with items, groups and separators', () => {
    render(
      <DropdownMenu open>
        <DropdownMenuTrigger>Menu</DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuLabel>Label</DropdownMenuLabel>
          <DropdownMenuItem>Item</DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuCheckboxItem checked>Checkbox</DropdownMenuCheckboxItem>
          <DropdownMenuRadioGroup value="x">
            <DropdownMenuRadioItem value="x">Radio</DropdownMenuRadioItem>
          </DropdownMenuRadioGroup>
          <DropdownMenuSub>
            <DropdownMenuSubTrigger>Sub</DropdownMenuSubTrigger>
            <DropdownMenuSubContent>
              <DropdownMenuItem>Nested</DropdownMenuItem>
            </DropdownMenuSubContent>
          </DropdownMenuSub>
          <DropdownMenuShortcut>Ctrl K</DropdownMenuShortcut>
        </DropdownMenuContent>
      </DropdownMenu>,
    )
    expect(screen.getByText('Item')).toBeInTheDocument()
    expect(screen.getByText('Label')).toBeInTheDocument()
    expect(screen.getByText('Checkbox')).toBeInTheDocument()
    expect(screen.getByText('Radio')).toBeInTheDocument()
    expect(screen.getByText('Ctrl K')).toBeInTheDocument()
  })
})

describe('ui/drawer', () => {
  it('renders a drawer with header, footer and content', () => {
    render(
      <Drawer open>
        <DrawerTrigger>Open drawer</DrawerTrigger>
        <DrawerContent>
          <DrawerHeader>
            <DrawerTitle>Drawer title</DrawerTitle>
            <DrawerDescription>Drawer description</DrawerDescription>
          </DrawerHeader>
          <DrawerFooter>Drawer footer</DrawerFooter>
        </DrawerContent>
      </Drawer>,
    )
    expect(screen.getByText('Drawer title')).toBeInTheDocument()
    expect(screen.getByText('Drawer description')).toBeInTheDocument()
    expect(screen.getByText('Drawer footer')).toBeInTheDocument()
  })
})

describe('ui/command', () => {
  it('renders the command palette family', () => {
    render(
      <Command>
        <CommandInput placeholder="Search" />
        <CommandList>
          <CommandEmpty>No results</CommandEmpty>
          <CommandGroup heading="Group">
            <CommandItem>Item</CommandItem>
            <CommandShortcut>Enter</CommandShortcut>
          </CommandGroup>
          <CommandSeparator />
        </CommandList>
      </Command>,
    )
    expect(screen.getByPlaceholderText('Search')).toBeInTheDocument()
    expect(screen.getByText('Item')).toBeInTheDocument()
  })

  it('renders the command dialog', () => {
    render(
      <CommandDialog open>
        <CommandInput placeholder="Find" />
        <CommandList>
          <CommandItem>Payload</CommandItem>
        </CommandList>
      </CommandDialog>,
    )
    expect(screen.getByPlaceholderText('Find')).toBeInTheDocument()
    expect(screen.getByText('Payload')).toBeInTheDocument()
  })
})
