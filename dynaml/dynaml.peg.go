package dynaml

import (
	"fmt"
	"math"
	"sort"
	"strconv"
)

const endSymbol rune = 1114112

/* The rule types inferred from the grammar are below. */
type pegRule uint8

const (
	ruleUnknown pegRule = iota
	ruleDynaml
	rulePrefer
	ruleMarkedExpression
	ruleSubsequentMarker
	ruleMarker
	ruleExpression
	ruleLevel7
	ruleOr
	ruleLevel6
	ruleConditional
	ruleLevel5
	ruleConcatenation
	ruleLevel4
	ruleLogOr
	ruleLogAnd
	ruleLevel3
	ruleComparison
	ruleCompareOp
	ruleLevel2
	ruleAddition
	ruleSubtraction
	ruleLevel1
	ruleMultiplication
	ruleDivision
	ruleModulo
	ruleLevel0
	ruleChained
	ruleChainedQualifiedExpression
	ruleChainedRef
	ruleChainedDynRef
	ruleSlice
	ruleChainedCall
	ruleArguments
	ruleNextExpression
	ruleSubstitution
	ruleNot
	ruleGrouped
	ruleRange
	ruleInteger
	ruleString
	ruleBoolean
	ruleNil
	ruleUndefined
	ruleList
	ruleContents
	ruleMap
	ruleCreateMap
	ruleAssignments
	ruleAssignment
	ruleMerge
	ruleRefMerge
	ruleSimpleMerge
	ruleReplace
	ruleRequired
	ruleOn
	ruleAuto
	ruleMapping
	ruleSum
	ruleLambda
	ruleLambdaRef
	ruleLambdaExpr
	ruleNextName
	ruleName
	ruleReference
	ruleFollowUpRef
	ruleKey
	ruleIndex
	ruleIP
	rulews
	rulereq_ws

	rulePre
	ruleIn
	ruleSuf
)

var rul3s = [...]string{
	"Unknown",
	"Dynaml",
	"Prefer",
	"MarkedExpression",
	"SubsequentMarker",
	"Marker",
	"Expression",
	"Level7",
	"Or",
	"Level6",
	"Conditional",
	"Level5",
	"Concatenation",
	"Level4",
	"LogOr",
	"LogAnd",
	"Level3",
	"Comparison",
	"CompareOp",
	"Level2",
	"Addition",
	"Subtraction",
	"Level1",
	"Multiplication",
	"Division",
	"Modulo",
	"Level0",
	"Chained",
	"ChainedQualifiedExpression",
	"ChainedRef",
	"ChainedDynRef",
	"Slice",
	"ChainedCall",
	"Arguments",
	"NextExpression",
	"Substitution",
	"Not",
	"Grouped",
	"Range",
	"Integer",
	"String",
	"Boolean",
	"Nil",
	"Undefined",
	"List",
	"Contents",
	"Map",
	"CreateMap",
	"Assignments",
	"Assignment",
	"Merge",
	"RefMerge",
	"SimpleMerge",
	"Replace",
	"Required",
	"On",
	"Auto",
	"Mapping",
	"Sum",
	"Lambda",
	"LambdaRef",
	"LambdaExpr",
	"NextName",
	"Name",
	"Reference",
	"FollowUpRef",
	"Key",
	"Index",
	"IP",
	"ws",
	"req_ws",

	"Pre_",
	"_In_",
	"_Suf",
}

type tokenTree interface {
	Print()
	PrintSyntax()
	PrintSyntaxTree(buffer string)
	Add(rule pegRule, begin, end, next uint32, depth int)
	Expand(index int) tokenTree
	Tokens() <-chan token32
	AST() *node32
	Error() []token32
	trim(length int)
}

type node32 struct {
	token32
	up, next *node32
}

func (node *node32) print(depth int, buffer string) {
	for node != nil {
		for c := 0; c < depth; c++ {
			fmt.Printf(" ")
		}
		fmt.Printf("\x1B[34m%v\x1B[m %v\n", rul3s[node.pegRule], strconv.Quote(string(([]rune(buffer)[node.begin:node.end]))))
		if node.up != nil {
			node.up.print(depth+1, buffer)
		}
		node = node.next
	}
}

func (node *node32) Print(buffer string) {
	node.print(0, buffer)
}

type element struct {
	node *node32
	down *element
}

/* ${@} bit structure for abstract syntax tree */
type token32 struct {
	pegRule
	begin, end, next uint32
}

func (t *token32) isZero() bool {
	return t.pegRule == ruleUnknown && t.begin == 0 && t.end == 0 && t.next == 0
}

func (t *token32) isParentOf(u token32) bool {
	return t.begin <= u.begin && t.end >= u.end && t.next > u.next
}

func (t *token32) getToken32() token32 {
	return token32{pegRule: t.pegRule, begin: uint32(t.begin), end: uint32(t.end), next: uint32(t.next)}
}

func (t *token32) String() string {
	return fmt.Sprintf("\x1B[34m%v\x1B[m %v %v %v", rul3s[t.pegRule], t.begin, t.end, t.next)
}

type tokens32 struct {
	tree    []token32
	ordered [][]token32
}

func (t *tokens32) trim(length int) {
	t.tree = t.tree[0:length]
}

func (t *tokens32) Print() {
	for _, token := range t.tree {
		fmt.Println(token.String())
	}
}

func (t *tokens32) Order() [][]token32 {
	if t.ordered != nil {
		return t.ordered
	}

	depths := make([]int32, 1, math.MaxInt16)
	for i, token := range t.tree {
		if token.pegRule == ruleUnknown {
			t.tree = t.tree[:i]
			break
		}
		depth := int(token.next)
		if length := len(depths); depth >= length {
			depths = depths[:depth+1]
		}
		depths[depth]++
	}
	depths = append(depths, 0)

	ordered, pool := make([][]token32, len(depths)), make([]token32, len(t.tree)+len(depths))
	for i, depth := range depths {
		depth++
		ordered[i], pool, depths[i] = pool[:depth], pool[depth:], 0
	}

	for i, token := range t.tree {
		depth := token.next
		token.next = uint32(i)
		ordered[depth][depths[depth]] = token
		depths[depth]++
	}
	t.ordered = ordered
	return ordered
}

type state32 struct {
	token32
	depths []int32
	leaf   bool
}

func (t *tokens32) AST() *node32 {
	tokens := t.Tokens()
	stack := &element{node: &node32{token32: <-tokens}}
	for token := range tokens {
		if token.begin == token.end {
			continue
		}
		node := &node32{token32: token}
		for stack != nil && stack.node.begin >= token.begin && stack.node.end <= token.end {
			stack.node.next = node.up
			node.up = stack.node
			stack = stack.down
		}
		stack = &element{node: node, down: stack}
	}
	return stack.node
}

func (t *tokens32) PreOrder() (<-chan state32, [][]token32) {
	s, ordered := make(chan state32, 6), t.Order()
	go func() {
		var states [8]state32
		for i := range states {
			states[i].depths = make([]int32, len(ordered))
		}
		depths, state, depth := make([]int32, len(ordered)), 0, 1
		write := func(t token32, leaf bool) {
			S := states[state]
			state, S.pegRule, S.begin, S.end, S.next, S.leaf = (state+1)%8, t.pegRule, t.begin, t.end, uint32(depth), leaf
			copy(S.depths, depths)
			s <- S
		}

		states[state].token32 = ordered[0][0]
		depths[0]++
		state++
		a, b := ordered[depth-1][depths[depth-1]-1], ordered[depth][depths[depth]]
	depthFirstSearch:
		for {
			for {
				if i := depths[depth]; i > 0 {
					if c, j := ordered[depth][i-1], depths[depth-1]; a.isParentOf(c) &&
						(j < 2 || !ordered[depth-1][j-2].isParentOf(c)) {
						if c.end != b.begin {
							write(token32{pegRule: ruleIn, begin: c.end, end: b.begin}, true)
						}
						break
					}
				}

				if a.begin < b.begin {
					write(token32{pegRule: rulePre, begin: a.begin, end: b.begin}, true)
				}
				break
			}

			next := depth + 1
			if c := ordered[next][depths[next]]; c.pegRule != ruleUnknown && b.isParentOf(c) {
				write(b, false)
				depths[depth]++
				depth, a, b = next, b, c
				continue
			}

			write(b, true)
			depths[depth]++
			c, parent := ordered[depth][depths[depth]], true
			for {
				if c.pegRule != ruleUnknown && a.isParentOf(c) {
					b = c
					continue depthFirstSearch
				} else if parent && b.end != a.end {
					write(token32{pegRule: ruleSuf, begin: b.end, end: a.end}, true)
				}

				depth--
				if depth > 0 {
					a, b, c = ordered[depth-1][depths[depth-1]-1], a, ordered[depth][depths[depth]]
					parent = a.isParentOf(b)
					continue
				}

				break depthFirstSearch
			}
		}

		close(s)
	}()
	return s, ordered
}

func (t *tokens32) PrintSyntax() {
	tokens, ordered := t.PreOrder()
	max := -1
	for token := range tokens {
		if !token.leaf {
			fmt.Printf("%v", token.begin)
			for i, leaf, depths := 0, int(token.next), token.depths; i < leaf; i++ {
				fmt.Printf(" \x1B[36m%v\x1B[m", rul3s[ordered[i][depths[i]-1].pegRule])
			}
			fmt.Printf(" \x1B[36m%v\x1B[m\n", rul3s[token.pegRule])
		} else if token.begin == token.end {
			fmt.Printf("%v", token.begin)
			for i, leaf, depths := 0, int(token.next), token.depths; i < leaf; i++ {
				fmt.Printf(" \x1B[31m%v\x1B[m", rul3s[ordered[i][depths[i]-1].pegRule])
			}
			fmt.Printf(" \x1B[31m%v\x1B[m\n", rul3s[token.pegRule])
		} else {
			for c, end := token.begin, token.end; c < end; c++ {
				if i := int(c); max+1 < i {
					for j := max; j < i; j++ {
						fmt.Printf("skip %v %v\n", j, token.String())
					}
					max = i
				} else if i := int(c); i <= max {
					for j := i; j <= max; j++ {
						fmt.Printf("dupe %v %v\n", j, token.String())
					}
				} else {
					max = int(c)
				}
				fmt.Printf("%v", c)
				for i, leaf, depths := 0, int(token.next), token.depths; i < leaf; i++ {
					fmt.Printf(" \x1B[34m%v\x1B[m", rul3s[ordered[i][depths[i]-1].pegRule])
				}
				fmt.Printf(" \x1B[34m%v\x1B[m\n", rul3s[token.pegRule])
			}
			fmt.Printf("\n")
		}
	}
}

func (t *tokens32) PrintSyntaxTree(buffer string) {
	tokens, _ := t.PreOrder()
	for token := range tokens {
		for c := 0; c < int(token.next); c++ {
			fmt.Printf(" ")
		}
		fmt.Printf("\x1B[34m%v\x1B[m %v\n", rul3s[token.pegRule], strconv.Quote(string(([]rune(buffer)[token.begin:token.end]))))
	}
}

func (t *tokens32) Add(rule pegRule, begin, end, depth uint32, index int) {
	t.tree[index] = token32{pegRule: rule, begin: uint32(begin), end: uint32(end), next: uint32(depth)}
}

func (t *tokens32) Tokens() <-chan token32 {
	s := make(chan token32, 16)
	go func() {
		for _, v := range t.tree {
			s <- v.getToken32()
		}
		close(s)
	}()
	return s
}

func (t *tokens32) Error() []token32 {
	ordered := t.Order()
	length := len(ordered)
	tokens, length := make([]token32, length), length-1
	for i := range tokens {
		o := ordered[length-i]
		if len(o) > 1 {
			tokens[i] = o[len(o)-2].getToken32()
		}
	}
	return tokens
}

/*func (t *tokens16) Expand(index int) tokenTree {
	tree := t.tree
	if index >= len(tree) {
		expanded := make([]token32, 2 * len(tree))
		for i, v := range tree {
			expanded[i] = v.getToken32()
		}
		return &tokens32{tree: expanded}
	}
	return nil
}*/

func (t *tokens32) Expand(index int) tokenTree {
	tree := t.tree
	if index >= len(tree) {
		expanded := make([]token32, 2*len(tree))
		copy(expanded, tree)
		t.tree = expanded
	}
	return nil
}

type DynamlGrammar struct {
	Buffer string
	buffer []rune
	rules  [71]func() bool
	Parse  func(rule ...int) error
	Reset  func()
	Pretty bool
	tokenTree
}

type textPosition struct {
	line, symbol int
}

type textPositionMap map[int]textPosition

func translatePositions(buffer []rune, positions []int) textPositionMap {
	length, translations, j, line, symbol := len(positions), make(textPositionMap, len(positions)), 0, 1, 0
	sort.Ints(positions)

search:
	for i, c := range buffer {
		if c == '\n' {
			line, symbol = line+1, 0
		} else {
			symbol++
		}
		if i == positions[j] {
			translations[positions[j]] = textPosition{line, symbol}
			for j++; j < length; j++ {
				if i != positions[j] {
					continue search
				}
			}
			break search
		}
	}

	return translations
}

type parseError struct {
	p   *DynamlGrammar
	max token32
}

func (e *parseError) Error() string {
	tokens, error := []token32{e.max}, "\n"
	positions, p := make([]int, 2*len(tokens)), 0
	for _, token := range tokens {
		positions[p], p = int(token.begin), p+1
		positions[p], p = int(token.end), p+1
	}
	translations := translatePositions(e.p.buffer, positions)
	format := "parse error near %v (line %v symbol %v - line %v symbol %v):\n%v\n"
	if e.p.Pretty {
		format = "parse error near \x1B[34m%v\x1B[m (line %v symbol %v - line %v symbol %v):\n%v\n"
	}
	for _, token := range tokens {
		begin, end := int(token.begin), int(token.end)
		error += fmt.Sprintf(format,
			rul3s[token.pegRule],
			translations[begin].line, translations[begin].symbol,
			translations[end].line, translations[end].symbol,
			strconv.Quote(string(e.p.buffer[begin:end])))
	}

	return error
}

func (p *DynamlGrammar) PrintSyntaxTree() {
	p.tokenTree.PrintSyntaxTree(p.Buffer)
}

func (p *DynamlGrammar) Highlighter() {
	p.tokenTree.PrintSyntax()
}

func (p *DynamlGrammar) Init() {
	p.buffer = []rune(p.Buffer)
	if len(p.buffer) == 0 || p.buffer[len(p.buffer)-1] != endSymbol {
		p.buffer = append(p.buffer, endSymbol)
	}

	var tree tokenTree = &tokens32{tree: make([]token32, math.MaxInt16)}
	var max token32
	position, depth, tokenIndex, buffer, _rules := uint32(0), uint32(0), 0, p.buffer, p.rules

	p.Parse = func(rule ...int) error {
		r := 1
		if len(rule) > 0 {
			r = rule[0]
		}
		matches := p.rules[r]()
		p.tokenTree = tree
		if matches {
			p.tokenTree.trim(tokenIndex)
			return nil
		}
		return &parseError{p, max}
	}

	p.Reset = func() {
		position, tokenIndex, depth = 0, 0, 0
	}

	add := func(rule pegRule, begin uint32) {
		if t := tree.Expand(tokenIndex); t != nil {
			tree = t
		}
		tree.Add(rule, begin, position, depth, tokenIndex)
		tokenIndex++
		if begin != position && position > max.end {
			max = token32{rule, begin, position, depth}
		}
	}

	matchDot := func() bool {
		if buffer[position] != endSymbol {
			position++
			return true
		}
		return false
	}

	/*matchChar := func(c byte) bool {
		if buffer[position] == c {
			position++
			return true
		}
		return false
	}*/

	/*matchRange := func(lower byte, upper byte) bool {
		if c := buffer[position]; c >= lower && c <= upper {
			position++
			return true
		}
		return false
	}*/

	_rules = [...]func() bool{
		nil,
		/* 0 Dynaml <- <((Prefer / MarkedExpression / Expression) !.)> */
		func() bool {
			position0, tokenIndex0, depth0 := position, tokenIndex, depth
			{
				position1 := position
				depth++
				{
					position2, tokenIndex2, depth2 := position, tokenIndex, depth
					if !_rules[rulePrefer]() {
						goto l3
					}
					goto l2
				l3:
					position, tokenIndex, depth = position2, tokenIndex2, depth2
					if !_rules[ruleMarkedExpression]() {
						goto l4
					}
					goto l2
				l4:
					position, tokenIndex, depth = position2, tokenIndex2, depth2
					if !_rules[ruleExpression]() {
						goto l0
					}
				}
			l2:
				{
					position5, tokenIndex5, depth5 := position, tokenIndex, depth
					if !matchDot() {
						goto l5
					}
					goto l0
				l5:
					position, tokenIndex, depth = position5, tokenIndex5, depth5
				}
				depth--
				add(ruleDynaml, position1)
			}
			return true
		l0:
			position, tokenIndex, depth = position0, tokenIndex0, depth0
			return false
		},
		/* 1 Prefer <- <(ws ('p' 'r' 'e' 'f' 'e' 'r') req_ws Expression)> */
		func() bool {
			position6, tokenIndex6, depth6 := position, tokenIndex, depth
			{
				position7 := position
				depth++
				if !_rules[rulews]() {
					goto l6
				}
				if buffer[position] != rune('p') {
					goto l6
				}
				position++
				if buffer[position] != rune('r') {
					goto l6
				}
				position++
				if buffer[position] != rune('e') {
					goto l6
				}
				position++
				if buffer[position] != rune('f') {
					goto l6
				}
				position++
				if buffer[position] != rune('e') {
					goto l6
				}
				position++
				if buffer[position] != rune('r') {
					goto l6
				}
				position++
				if !_rules[rulereq_ws]() {
					goto l6
				}
				if !_rules[ruleExpression]() {
					goto l6
				}
				depth--
				add(rulePrefer, position7)
			}
			return true
		l6:
			position, tokenIndex, depth = position6, tokenIndex6, depth6
			return false
		},
		/* 2 MarkedExpression <- <(ws Marker (req_ws SubsequentMarker)* ws Grouped? ws)> */
		func() bool {
			position8, tokenIndex8, depth8 := position, tokenIndex, depth
			{
				position9 := position
				depth++
				if !_rules[rulews]() {
					goto l8
				}
				if !_rules[ruleMarker]() {
					goto l8
				}
			l10:
				{
					position11, tokenIndex11, depth11 := position, tokenIndex, depth
					if !_rules[rulereq_ws]() {
						goto l11
					}
					if !_rules[ruleSubsequentMarker]() {
						goto l11
					}
					goto l10
				l11:
					position, tokenIndex, depth = position11, tokenIndex11, depth11
				}
				if !_rules[rulews]() {
					goto l8
				}
				{
					position12, tokenIndex12, depth12 := position, tokenIndex, depth
					if !_rules[ruleGrouped]() {
						goto l12
					}
					goto l13
				l12:
					position, tokenIndex, depth = position12, tokenIndex12, depth12
				}
			l13:
				if !_rules[rulews]() {
					goto l8
				}
				depth--
				add(ruleMarkedExpression, position9)
			}
			return true
		l8:
			position, tokenIndex, depth = position8, tokenIndex8, depth8
			return false
		},
		/* 3 SubsequentMarker <- <Marker> */
		func() bool {
			position14, tokenIndex14, depth14 := position, tokenIndex, depth
			{
				position15 := position
				depth++
				if !_rules[ruleMarker]() {
					goto l14
				}
				depth--
				add(ruleSubsequentMarker, position15)
			}
			return true
		l14:
			position, tokenIndex, depth = position14, tokenIndex14, depth14
			return false
		},
		/* 4 Marker <- <('&' (('t' 'e' 'm' 'p' 'l' 'a' 't' 'e') / ('t' 'e' 'm' 'p' 'o' 'r' 'a' 'r' 'y') / ('l' 'o' 'c' 'a' 'l')))> */
		func() bool {
			position16, tokenIndex16, depth16 := position, tokenIndex, depth
			{
				position17 := position
				depth++
				if buffer[position] != rune('&') {
					goto l16
				}
				position++
				{
					position18, tokenIndex18, depth18 := position, tokenIndex, depth
					if buffer[position] != rune('t') {
						goto l19
					}
					position++
					if buffer[position] != rune('e') {
						goto l19
					}
					position++
					if buffer[position] != rune('m') {
						goto l19
					}
					position++
					if buffer[position] != rune('p') {
						goto l19
					}
					position++
					if buffer[position] != rune('l') {
						goto l19
					}
					position++
					if buffer[position] != rune('a') {
						goto l19
					}
					position++
					if buffer[position] != rune('t') {
						goto l19
					}
					position++
					if buffer[position] != rune('e') {
						goto l19
					}
					position++
					goto l18
				l19:
					position, tokenIndex, depth = position18, tokenIndex18, depth18
					if buffer[position] != rune('t') {
						goto l20
					}
					position++
					if buffer[position] != rune('e') {
						goto l20
					}
					position++
					if buffer[position] != rune('m') {
						goto l20
					}
					position++
					if buffer[position] != rune('p') {
						goto l20
					}
					position++
					if buffer[position] != rune('o') {
						goto l20
					}
					position++
					if buffer[position] != rune('r') {
						goto l20
					}
					position++
					if buffer[position] != rune('a') {
						goto l20
					}
					position++
					if buffer[position] != rune('r') {
						goto l20
					}
					position++
					if buffer[position] != rune('y') {
						goto l20
					}
					position++
					goto l18
				l20:
					position, tokenIndex, depth = position18, tokenIndex18, depth18
					if buffer[position] != rune('l') {
						goto l16
					}
					position++
					if buffer[position] != rune('o') {
						goto l16
					}
					position++
					if buffer[position] != rune('c') {
						goto l16
					}
					position++
					if buffer[position] != rune('a') {
						goto l16
					}
					position++
					if buffer[position] != rune('l') {
						goto l16
					}
					position++
				}
			l18:
				depth--
				add(ruleMarker, position17)
			}
			return true
		l16:
			position, tokenIndex, depth = position16, tokenIndex16, depth16
			return false
		},
		/* 5 Expression <- <(ws (LambdaExpr / Level7) ws)> */
		func() bool {
			position21, tokenIndex21, depth21 := position, tokenIndex, depth
			{
				position22 := position
				depth++
				if !_rules[rulews]() {
					goto l21
				}
				{
					position23, tokenIndex23, depth23 := position, tokenIndex, depth
					if !_rules[ruleLambdaExpr]() {
						goto l24
					}
					goto l23
				l24:
					position, tokenIndex, depth = position23, tokenIndex23, depth23
					if !_rules[ruleLevel7]() {
						goto l21
					}
				}
			l23:
				if !_rules[rulews]() {
					goto l21
				}
				depth--
				add(ruleExpression, position22)
			}
			return true
		l21:
			position, tokenIndex, depth = position21, tokenIndex21, depth21
			return false
		},
		/* 6 Level7 <- <(Level6 (req_ws Or)*)> */
		func() bool {
			position25, tokenIndex25, depth25 := position, tokenIndex, depth
			{
				position26 := position
				depth++
				if !_rules[ruleLevel6]() {
					goto l25
				}
			l27:
				{
					position28, tokenIndex28, depth28 := position, tokenIndex, depth
					if !_rules[rulereq_ws]() {
						goto l28
					}
					if !_rules[ruleOr]() {
						goto l28
					}
					goto l27
				l28:
					position, tokenIndex, depth = position28, tokenIndex28, depth28
				}
				depth--
				add(ruleLevel7, position26)
			}
			return true
		l25:
			position, tokenIndex, depth = position25, tokenIndex25, depth25
			return false
		},
		/* 7 Or <- <('|' '|' req_ws Level6)> */
		func() bool {
			position29, tokenIndex29, depth29 := position, tokenIndex, depth
			{
				position30 := position
				depth++
				if buffer[position] != rune('|') {
					goto l29
				}
				position++
				if buffer[position] != rune('|') {
					goto l29
				}
				position++
				if !_rules[rulereq_ws]() {
					goto l29
				}
				if !_rules[ruleLevel6]() {
					goto l29
				}
				depth--
				add(ruleOr, position30)
			}
			return true
		l29:
			position, tokenIndex, depth = position29, tokenIndex29, depth29
			return false
		},
		/* 8 Level6 <- <(Conditional / Level5)> */
		func() bool {
			position31, tokenIndex31, depth31 := position, tokenIndex, depth
			{
				position32 := position
				depth++
				{
					position33, tokenIndex33, depth33 := position, tokenIndex, depth
					if !_rules[ruleConditional]() {
						goto l34
					}
					goto l33
				l34:
					position, tokenIndex, depth = position33, tokenIndex33, depth33
					if !_rules[ruleLevel5]() {
						goto l31
					}
				}
			l33:
				depth--
				add(ruleLevel6, position32)
			}
			return true
		l31:
			position, tokenIndex, depth = position31, tokenIndex31, depth31
			return false
		},
		/* 9 Conditional <- <(Level5 ws '?' Expression ':' Expression)> */
		func() bool {
			position35, tokenIndex35, depth35 := position, tokenIndex, depth
			{
				position36 := position
				depth++
				if !_rules[ruleLevel5]() {
					goto l35
				}
				if !_rules[rulews]() {
					goto l35
				}
				if buffer[position] != rune('?') {
					goto l35
				}
				position++
				if !_rules[ruleExpression]() {
					goto l35
				}
				if buffer[position] != rune(':') {
					goto l35
				}
				position++
				if !_rules[ruleExpression]() {
					goto l35
				}
				depth--
				add(ruleConditional, position36)
			}
			return true
		l35:
			position, tokenIndex, depth = position35, tokenIndex35, depth35
			return false
		},
		/* 10 Level5 <- <(Level4 Concatenation*)> */
		func() bool {
			position37, tokenIndex37, depth37 := position, tokenIndex, depth
			{
				position38 := position
				depth++
				if !_rules[ruleLevel4]() {
					goto l37
				}
			l39:
				{
					position40, tokenIndex40, depth40 := position, tokenIndex, depth
					if !_rules[ruleConcatenation]() {
						goto l40
					}
					goto l39
				l40:
					position, tokenIndex, depth = position40, tokenIndex40, depth40
				}
				depth--
				add(ruleLevel5, position38)
			}
			return true
		l37:
			position, tokenIndex, depth = position37, tokenIndex37, depth37
			return false
		},
		/* 11 Concatenation <- <(req_ws Level4)> */
		func() bool {
			position41, tokenIndex41, depth41 := position, tokenIndex, depth
			{
				position42 := position
				depth++
				if !_rules[rulereq_ws]() {
					goto l41
				}
				if !_rules[ruleLevel4]() {
					goto l41
				}
				depth--
				add(ruleConcatenation, position42)
			}
			return true
		l41:
			position, tokenIndex, depth = position41, tokenIndex41, depth41
			return false
		},
		/* 12 Level4 <- <(Level3 (req_ws (LogOr / LogAnd))*)> */
		func() bool {
			position43, tokenIndex43, depth43 := position, tokenIndex, depth
			{
				position44 := position
				depth++
				if !_rules[ruleLevel3]() {
					goto l43
				}
			l45:
				{
					position46, tokenIndex46, depth46 := position, tokenIndex, depth
					if !_rules[rulereq_ws]() {
						goto l46
					}
					{
						position47, tokenIndex47, depth47 := position, tokenIndex, depth
						if !_rules[ruleLogOr]() {
							goto l48
						}
						goto l47
					l48:
						position, tokenIndex, depth = position47, tokenIndex47, depth47
						if !_rules[ruleLogAnd]() {
							goto l46
						}
					}
				l47:
					goto l45
				l46:
					position, tokenIndex, depth = position46, tokenIndex46, depth46
				}
				depth--
				add(ruleLevel4, position44)
			}
			return true
		l43:
			position, tokenIndex, depth = position43, tokenIndex43, depth43
			return false
		},
		/* 13 LogOr <- <('-' 'o' 'r' req_ws Level3)> */
		func() bool {
			position49, tokenIndex49, depth49 := position, tokenIndex, depth
			{
				position50 := position
				depth++
				if buffer[position] != rune('-') {
					goto l49
				}
				position++
				if buffer[position] != rune('o') {
					goto l49
				}
				position++
				if buffer[position] != rune('r') {
					goto l49
				}
				position++
				if !_rules[rulereq_ws]() {
					goto l49
				}
				if !_rules[ruleLevel3]() {
					goto l49
				}
				depth--
				add(ruleLogOr, position50)
			}
			return true
		l49:
			position, tokenIndex, depth = position49, tokenIndex49, depth49
			return false
		},
		/* 14 LogAnd <- <('-' 'a' 'n' 'd' req_ws Level3)> */
		func() bool {
			position51, tokenIndex51, depth51 := position, tokenIndex, depth
			{
				position52 := position
				depth++
				if buffer[position] != rune('-') {
					goto l51
				}
				position++
				if buffer[position] != rune('a') {
					goto l51
				}
				position++
				if buffer[position] != rune('n') {
					goto l51
				}
				position++
				if buffer[position] != rune('d') {
					goto l51
				}
				position++
				if !_rules[rulereq_ws]() {
					goto l51
				}
				if !_rules[ruleLevel3]() {
					goto l51
				}
				depth--
				add(ruleLogAnd, position52)
			}
			return true
		l51:
			position, tokenIndex, depth = position51, tokenIndex51, depth51
			return false
		},
		/* 15 Level3 <- <(Level2 (req_ws Comparison)*)> */
		func() bool {
			position53, tokenIndex53, depth53 := position, tokenIndex, depth
			{
				position54 := position
				depth++
				if !_rules[ruleLevel2]() {
					goto l53
				}
			l55:
				{
					position56, tokenIndex56, depth56 := position, tokenIndex, depth
					if !_rules[rulereq_ws]() {
						goto l56
					}
					if !_rules[ruleComparison]() {
						goto l56
					}
					goto l55
				l56:
					position, tokenIndex, depth = position56, tokenIndex56, depth56
				}
				depth--
				add(ruleLevel3, position54)
			}
			return true
		l53:
			position, tokenIndex, depth = position53, tokenIndex53, depth53
			return false
		},
		/* 16 Comparison <- <(CompareOp req_ws Level2)> */
		func() bool {
			position57, tokenIndex57, depth57 := position, tokenIndex, depth
			{
				position58 := position
				depth++
				if !_rules[ruleCompareOp]() {
					goto l57
				}
				if !_rules[rulereq_ws]() {
					goto l57
				}
				if !_rules[ruleLevel2]() {
					goto l57
				}
				depth--
				add(ruleComparison, position58)
			}
			return true
		l57:
			position, tokenIndex, depth = position57, tokenIndex57, depth57
			return false
		},
		/* 17 CompareOp <- <(('=' '=') / ('!' '=') / ('<' '=') / ('>' '=') / '>' / '<' / '>')> */
		func() bool {
			position59, tokenIndex59, depth59 := position, tokenIndex, depth
			{
				position60 := position
				depth++
				{
					position61, tokenIndex61, depth61 := position, tokenIndex, depth
					if buffer[position] != rune('=') {
						goto l62
					}
					position++
					if buffer[position] != rune('=') {
						goto l62
					}
					position++
					goto l61
				l62:
					position, tokenIndex, depth = position61, tokenIndex61, depth61
					if buffer[position] != rune('!') {
						goto l63
					}
					position++
					if buffer[position] != rune('=') {
						goto l63
					}
					position++
					goto l61
				l63:
					position, tokenIndex, depth = position61, tokenIndex61, depth61
					if buffer[position] != rune('<') {
						goto l64
					}
					position++
					if buffer[position] != rune('=') {
						goto l64
					}
					position++
					goto l61
				l64:
					position, tokenIndex, depth = position61, tokenIndex61, depth61
					if buffer[position] != rune('>') {
						goto l65
					}
					position++
					if buffer[position] != rune('=') {
						goto l65
					}
					position++
					goto l61
				l65:
					position, tokenIndex, depth = position61, tokenIndex61, depth61
					if buffer[position] != rune('>') {
						goto l66
					}
					position++
					goto l61
				l66:
					position, tokenIndex, depth = position61, tokenIndex61, depth61
					if buffer[position] != rune('<') {
						goto l67
					}
					position++
					goto l61
				l67:
					position, tokenIndex, depth = position61, tokenIndex61, depth61
					if buffer[position] != rune('>') {
						goto l59
					}
					position++
				}
			l61:
				depth--
				add(ruleCompareOp, position60)
			}
			return true
		l59:
			position, tokenIndex, depth = position59, tokenIndex59, depth59
			return false
		},
		/* 18 Level2 <- <(Level1 (req_ws (Addition / Subtraction))*)> */
		func() bool {
			position68, tokenIndex68, depth68 := position, tokenIndex, depth
			{
				position69 := position
				depth++
				if !_rules[ruleLevel1]() {
					goto l68
				}
			l70:
				{
					position71, tokenIndex71, depth71 := position, tokenIndex, depth
					if !_rules[rulereq_ws]() {
						goto l71
					}
					{
						position72, tokenIndex72, depth72 := position, tokenIndex, depth
						if !_rules[ruleAddition]() {
							goto l73
						}
						goto l72
					l73:
						position, tokenIndex, depth = position72, tokenIndex72, depth72
						if !_rules[ruleSubtraction]() {
							goto l71
						}
					}
				l72:
					goto l70
				l71:
					position, tokenIndex, depth = position71, tokenIndex71, depth71
				}
				depth--
				add(ruleLevel2, position69)
			}
			return true
		l68:
			position, tokenIndex, depth = position68, tokenIndex68, depth68
			return false
		},
		/* 19 Addition <- <('+' req_ws Level1)> */
		func() bool {
			position74, tokenIndex74, depth74 := position, tokenIndex, depth
			{
				position75 := position
				depth++
				if buffer[position] != rune('+') {
					goto l74
				}
				position++
				if !_rules[rulereq_ws]() {
					goto l74
				}
				if !_rules[ruleLevel1]() {
					goto l74
				}
				depth--
				add(ruleAddition, position75)
			}
			return true
		l74:
			position, tokenIndex, depth = position74, tokenIndex74, depth74
			return false
		},
		/* 20 Subtraction <- <('-' req_ws Level1)> */
		func() bool {
			position76, tokenIndex76, depth76 := position, tokenIndex, depth
			{
				position77 := position
				depth++
				if buffer[position] != rune('-') {
					goto l76
				}
				position++
				if !_rules[rulereq_ws]() {
					goto l76
				}
				if !_rules[ruleLevel1]() {
					goto l76
				}
				depth--
				add(ruleSubtraction, position77)
			}
			return true
		l76:
			position, tokenIndex, depth = position76, tokenIndex76, depth76
			return false
		},
		/* 21 Level1 <- <(Level0 (req_ws (Multiplication / Division / Modulo))*)> */
		func() bool {
			position78, tokenIndex78, depth78 := position, tokenIndex, depth
			{
				position79 := position
				depth++
				if !_rules[ruleLevel0]() {
					goto l78
				}
			l80:
				{
					position81, tokenIndex81, depth81 := position, tokenIndex, depth
					if !_rules[rulereq_ws]() {
						goto l81
					}
					{
						position82, tokenIndex82, depth82 := position, tokenIndex, depth
						if !_rules[ruleMultiplication]() {
							goto l83
						}
						goto l82
					l83:
						position, tokenIndex, depth = position82, tokenIndex82, depth82
						if !_rules[ruleDivision]() {
							goto l84
						}
						goto l82
					l84:
						position, tokenIndex, depth = position82, tokenIndex82, depth82
						if !_rules[ruleModulo]() {
							goto l81
						}
					}
				l82:
					goto l80
				l81:
					position, tokenIndex, depth = position81, tokenIndex81, depth81
				}
				depth--
				add(ruleLevel1, position79)
			}
			return true
		l78:
			position, tokenIndex, depth = position78, tokenIndex78, depth78
			return false
		},
		/* 22 Multiplication <- <('*' req_ws Level0)> */
		func() bool {
			position85, tokenIndex85, depth85 := position, tokenIndex, depth
			{
				position86 := position
				depth++
				if buffer[position] != rune('*') {
					goto l85
				}
				position++
				if !_rules[rulereq_ws]() {
					goto l85
				}
				if !_rules[ruleLevel0]() {
					goto l85
				}
				depth--
				add(ruleMultiplication, position86)
			}
			return true
		l85:
			position, tokenIndex, depth = position85, tokenIndex85, depth85
			return false
		},
		/* 23 Division <- <('/' req_ws Level0)> */
		func() bool {
			position87, tokenIndex87, depth87 := position, tokenIndex, depth
			{
				position88 := position
				depth++
				if buffer[position] != rune('/') {
					goto l87
				}
				position++
				if !_rules[rulereq_ws]() {
					goto l87
				}
				if !_rules[ruleLevel0]() {
					goto l87
				}
				depth--
				add(ruleDivision, position88)
			}
			return true
		l87:
			position, tokenIndex, depth = position87, tokenIndex87, depth87
			return false
		},
		/* 24 Modulo <- <('%' req_ws Level0)> */
		func() bool {
			position89, tokenIndex89, depth89 := position, tokenIndex, depth
			{
				position90 := position
				depth++
				if buffer[position] != rune('%') {
					goto l89
				}
				position++
				if !_rules[rulereq_ws]() {
					goto l89
				}
				if !_rules[ruleLevel0]() {
					goto l89
				}
				depth--
				add(ruleModulo, position90)
			}
			return true
		l89:
			position, tokenIndex, depth = position89, tokenIndex89, depth89
			return false
		},
		/* 25 Level0 <- <(IP / String / Integer / Boolean / Undefined / Nil / Not / Substitution / Merge / Auto / Lambda / Chained)> */
		func() bool {
			position91, tokenIndex91, depth91 := position, tokenIndex, depth
			{
				position92 := position
				depth++
				{
					position93, tokenIndex93, depth93 := position, tokenIndex, depth
					if !_rules[ruleIP]() {
						goto l94
					}
					goto l93
				l94:
					position, tokenIndex, depth = position93, tokenIndex93, depth93
					if !_rules[ruleString]() {
						goto l95
					}
					goto l93
				l95:
					position, tokenIndex, depth = position93, tokenIndex93, depth93
					if !_rules[ruleInteger]() {
						goto l96
					}
					goto l93
				l96:
					position, tokenIndex, depth = position93, tokenIndex93, depth93
					if !_rules[ruleBoolean]() {
						goto l97
					}
					goto l93
				l97:
					position, tokenIndex, depth = position93, tokenIndex93, depth93
					if !_rules[ruleUndefined]() {
						goto l98
					}
					goto l93
				l98:
					position, tokenIndex, depth = position93, tokenIndex93, depth93
					if !_rules[ruleNil]() {
						goto l99
					}
					goto l93
				l99:
					position, tokenIndex, depth = position93, tokenIndex93, depth93
					if !_rules[ruleNot]() {
						goto l100
					}
					goto l93
				l100:
					position, tokenIndex, depth = position93, tokenIndex93, depth93
					if !_rules[ruleSubstitution]() {
						goto l101
					}
					goto l93
				l101:
					position, tokenIndex, depth = position93, tokenIndex93, depth93
					if !_rules[ruleMerge]() {
						goto l102
					}
					goto l93
				l102:
					position, tokenIndex, depth = position93, tokenIndex93, depth93
					if !_rules[ruleAuto]() {
						goto l103
					}
					goto l93
				l103:
					position, tokenIndex, depth = position93, tokenIndex93, depth93
					if !_rules[ruleLambda]() {
						goto l104
					}
					goto l93
				l104:
					position, tokenIndex, depth = position93, tokenIndex93, depth93
					if !_rules[ruleChained]() {
						goto l91
					}
				}
			l93:
				depth--
				add(ruleLevel0, position92)
			}
			return true
		l91:
			position, tokenIndex, depth = position91, tokenIndex91, depth91
			return false
		},
		/* 26 Chained <- <((Mapping / Sum / List / Map / Range / Grouped / Reference) ChainedQualifiedExpression*)> */
		func() bool {
			position105, tokenIndex105, depth105 := position, tokenIndex, depth
			{
				position106 := position
				depth++
				{
					position107, tokenIndex107, depth107 := position, tokenIndex, depth
					if !_rules[ruleMapping]() {
						goto l108
					}
					goto l107
				l108:
					position, tokenIndex, depth = position107, tokenIndex107, depth107
					if !_rules[ruleSum]() {
						goto l109
					}
					goto l107
				l109:
					position, tokenIndex, depth = position107, tokenIndex107, depth107
					if !_rules[ruleList]() {
						goto l110
					}
					goto l107
				l110:
					position, tokenIndex, depth = position107, tokenIndex107, depth107
					if !_rules[ruleMap]() {
						goto l111
					}
					goto l107
				l111:
					position, tokenIndex, depth = position107, tokenIndex107, depth107
					if !_rules[ruleRange]() {
						goto l112
					}
					goto l107
				l112:
					position, tokenIndex, depth = position107, tokenIndex107, depth107
					if !_rules[ruleGrouped]() {
						goto l113
					}
					goto l107
				l113:
					position, tokenIndex, depth = position107, tokenIndex107, depth107
					if !_rules[ruleReference]() {
						goto l105
					}
				}
			l107:
			l114:
				{
					position115, tokenIndex115, depth115 := position, tokenIndex, depth
					if !_rules[ruleChainedQualifiedExpression]() {
						goto l115
					}
					goto l114
				l115:
					position, tokenIndex, depth = position115, tokenIndex115, depth115
				}
				depth--
				add(ruleChained, position106)
			}
			return true
		l105:
			position, tokenIndex, depth = position105, tokenIndex105, depth105
			return false
		},
		/* 27 ChainedQualifiedExpression <- <(ChainedCall / ('.' (ChainedRef / ChainedDynRef / Slice)))> */
		func() bool {
			position116, tokenIndex116, depth116 := position, tokenIndex, depth
			{
				position117 := position
				depth++
				{
					position118, tokenIndex118, depth118 := position, tokenIndex, depth
					if !_rules[ruleChainedCall]() {
						goto l119
					}
					goto l118
				l119:
					position, tokenIndex, depth = position118, tokenIndex118, depth118
					if buffer[position] != rune('.') {
						goto l116
					}
					position++
					{
						position120, tokenIndex120, depth120 := position, tokenIndex, depth
						if !_rules[ruleChainedRef]() {
							goto l121
						}
						goto l120
					l121:
						position, tokenIndex, depth = position120, tokenIndex120, depth120
						if !_rules[ruleChainedDynRef]() {
							goto l122
						}
						goto l120
					l122:
						position, tokenIndex, depth = position120, tokenIndex120, depth120
						if !_rules[ruleSlice]() {
							goto l116
						}
					}
				l120:
				}
			l118:
				depth--
				add(ruleChainedQualifiedExpression, position117)
			}
			return true
		l116:
			position, tokenIndex, depth = position116, tokenIndex116, depth116
			return false
		},
		/* 28 ChainedRef <- <((Key / Index) FollowUpRef)> */
		func() bool {
			position123, tokenIndex123, depth123 := position, tokenIndex, depth
			{
				position124 := position
				depth++
				{
					position125, tokenIndex125, depth125 := position, tokenIndex, depth
					if !_rules[ruleKey]() {
						goto l126
					}
					goto l125
				l126:
					position, tokenIndex, depth = position125, tokenIndex125, depth125
					if !_rules[ruleIndex]() {
						goto l123
					}
				}
			l125:
				if !_rules[ruleFollowUpRef]() {
					goto l123
				}
				depth--
				add(ruleChainedRef, position124)
			}
			return true
		l123:
			position, tokenIndex, depth = position123, tokenIndex123, depth123
			return false
		},
		/* 29 ChainedDynRef <- <('[' Expression ']')> */
		func() bool {
			position127, tokenIndex127, depth127 := position, tokenIndex, depth
			{
				position128 := position
				depth++
				if buffer[position] != rune('[') {
					goto l127
				}
				position++
				if !_rules[ruleExpression]() {
					goto l127
				}
				if buffer[position] != rune(']') {
					goto l127
				}
				position++
				depth--
				add(ruleChainedDynRef, position128)
			}
			return true
		l127:
			position, tokenIndex, depth = position127, tokenIndex127, depth127
			return false
		},
		/* 30 Slice <- <Range> */
		func() bool {
			position129, tokenIndex129, depth129 := position, tokenIndex, depth
			{
				position130 := position
				depth++
				if !_rules[ruleRange]() {
					goto l129
				}
				depth--
				add(ruleSlice, position130)
			}
			return true
		l129:
			position, tokenIndex, depth = position129, tokenIndex129, depth129
			return false
		},
		/* 31 ChainedCall <- <('(' Arguments ')')> */
		func() bool {
			position131, tokenIndex131, depth131 := position, tokenIndex, depth
			{
				position132 := position
				depth++
				if buffer[position] != rune('(') {
					goto l131
				}
				position++
				if !_rules[ruleArguments]() {
					goto l131
				}
				if buffer[position] != rune(')') {
					goto l131
				}
				position++
				depth--
				add(ruleChainedCall, position132)
			}
			return true
		l131:
			position, tokenIndex, depth = position131, tokenIndex131, depth131
			return false
		},
		/* 32 Arguments <- <(Expression NextExpression*)> */
		func() bool {
			position133, tokenIndex133, depth133 := position, tokenIndex, depth
			{
				position134 := position
				depth++
				if !_rules[ruleExpression]() {
					goto l133
				}
			l135:
				{
					position136, tokenIndex136, depth136 := position, tokenIndex, depth
					if !_rules[ruleNextExpression]() {
						goto l136
					}
					goto l135
				l136:
					position, tokenIndex, depth = position136, tokenIndex136, depth136
				}
				depth--
				add(ruleArguments, position134)
			}
			return true
		l133:
			position, tokenIndex, depth = position133, tokenIndex133, depth133
			return false
		},
		/* 33 NextExpression <- <(',' Expression)> */
		func() bool {
			position137, tokenIndex137, depth137 := position, tokenIndex, depth
			{
				position138 := position
				depth++
				if buffer[position] != rune(',') {
					goto l137
				}
				position++
				if !_rules[ruleExpression]() {
					goto l137
				}
				depth--
				add(ruleNextExpression, position138)
			}
			return true
		l137:
			position, tokenIndex, depth = position137, tokenIndex137, depth137
			return false
		},
		/* 34 Substitution <- <('*' Level0)> */
		func() bool {
			position139, tokenIndex139, depth139 := position, tokenIndex, depth
			{
				position140 := position
				depth++
				if buffer[position] != rune('*') {
					goto l139
				}
				position++
				if !_rules[ruleLevel0]() {
					goto l139
				}
				depth--
				add(ruleSubstitution, position140)
			}
			return true
		l139:
			position, tokenIndex, depth = position139, tokenIndex139, depth139
			return false
		},
		/* 35 Not <- <('!' ws Level0)> */
		func() bool {
			position141, tokenIndex141, depth141 := position, tokenIndex, depth
			{
				position142 := position
				depth++
				if buffer[position] != rune('!') {
					goto l141
				}
				position++
				if !_rules[rulews]() {
					goto l141
				}
				if !_rules[ruleLevel0]() {
					goto l141
				}
				depth--
				add(ruleNot, position142)
			}
			return true
		l141:
			position, tokenIndex, depth = position141, tokenIndex141, depth141
			return false
		},
		/* 36 Grouped <- <('(' Expression ')')> */
		func() bool {
			position143, tokenIndex143, depth143 := position, tokenIndex, depth
			{
				position144 := position
				depth++
				if buffer[position] != rune('(') {
					goto l143
				}
				position++
				if !_rules[ruleExpression]() {
					goto l143
				}
				if buffer[position] != rune(')') {
					goto l143
				}
				position++
				depth--
				add(ruleGrouped, position144)
			}
			return true
		l143:
			position, tokenIndex, depth = position143, tokenIndex143, depth143
			return false
		},
		/* 37 Range <- <('[' Expression ('.' '.') Expression ']')> */
		func() bool {
			position145, tokenIndex145, depth145 := position, tokenIndex, depth
			{
				position146 := position
				depth++
				if buffer[position] != rune('[') {
					goto l145
				}
				position++
				if !_rules[ruleExpression]() {
					goto l145
				}
				if buffer[position] != rune('.') {
					goto l145
				}
				position++
				if buffer[position] != rune('.') {
					goto l145
				}
				position++
				if !_rules[ruleExpression]() {
					goto l145
				}
				if buffer[position] != rune(']') {
					goto l145
				}
				position++
				depth--
				add(ruleRange, position146)
			}
			return true
		l145:
			position, tokenIndex, depth = position145, tokenIndex145, depth145
			return false
		},
		/* 38 Integer <- <('-'? [0-9] ([0-9] / '_')*)> */
		func() bool {
			position147, tokenIndex147, depth147 := position, tokenIndex, depth
			{
				position148 := position
				depth++
				{
					position149, tokenIndex149, depth149 := position, tokenIndex, depth
					if buffer[position] != rune('-') {
						goto l149
					}
					position++
					goto l150
				l149:
					position, tokenIndex, depth = position149, tokenIndex149, depth149
				}
			l150:
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l147
				}
				position++
			l151:
				{
					position152, tokenIndex152, depth152 := position, tokenIndex, depth
					{
						position153, tokenIndex153, depth153 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l154
						}
						position++
						goto l153
					l154:
						position, tokenIndex, depth = position153, tokenIndex153, depth153
						if buffer[position] != rune('_') {
							goto l152
						}
						position++
					}
				l153:
					goto l151
				l152:
					position, tokenIndex, depth = position152, tokenIndex152, depth152
				}
				depth--
				add(ruleInteger, position148)
			}
			return true
		l147:
			position, tokenIndex, depth = position147, tokenIndex147, depth147
			return false
		},
		/* 39 String <- <('"' (('\\' '"') / (!'"' .))* '"')> */
		func() bool {
			position155, tokenIndex155, depth155 := position, tokenIndex, depth
			{
				position156 := position
				depth++
				if buffer[position] != rune('"') {
					goto l155
				}
				position++
			l157:
				{
					position158, tokenIndex158, depth158 := position, tokenIndex, depth
					{
						position159, tokenIndex159, depth159 := position, tokenIndex, depth
						if buffer[position] != rune('\\') {
							goto l160
						}
						position++
						if buffer[position] != rune('"') {
							goto l160
						}
						position++
						goto l159
					l160:
						position, tokenIndex, depth = position159, tokenIndex159, depth159
						{
							position161, tokenIndex161, depth161 := position, tokenIndex, depth
							if buffer[position] != rune('"') {
								goto l161
							}
							position++
							goto l158
						l161:
							position, tokenIndex, depth = position161, tokenIndex161, depth161
						}
						if !matchDot() {
							goto l158
						}
					}
				l159:
					goto l157
				l158:
					position, tokenIndex, depth = position158, tokenIndex158, depth158
				}
				if buffer[position] != rune('"') {
					goto l155
				}
				position++
				depth--
				add(ruleString, position156)
			}
			return true
		l155:
			position, tokenIndex, depth = position155, tokenIndex155, depth155
			return false
		},
		/* 40 Boolean <- <(('t' 'r' 'u' 'e') / ('f' 'a' 'l' 's' 'e'))> */
		func() bool {
			position162, tokenIndex162, depth162 := position, tokenIndex, depth
			{
				position163 := position
				depth++
				{
					position164, tokenIndex164, depth164 := position, tokenIndex, depth
					if buffer[position] != rune('t') {
						goto l165
					}
					position++
					if buffer[position] != rune('r') {
						goto l165
					}
					position++
					if buffer[position] != rune('u') {
						goto l165
					}
					position++
					if buffer[position] != rune('e') {
						goto l165
					}
					position++
					goto l164
				l165:
					position, tokenIndex, depth = position164, tokenIndex164, depth164
					if buffer[position] != rune('f') {
						goto l162
					}
					position++
					if buffer[position] != rune('a') {
						goto l162
					}
					position++
					if buffer[position] != rune('l') {
						goto l162
					}
					position++
					if buffer[position] != rune('s') {
						goto l162
					}
					position++
					if buffer[position] != rune('e') {
						goto l162
					}
					position++
				}
			l164:
				depth--
				add(ruleBoolean, position163)
			}
			return true
		l162:
			position, tokenIndex, depth = position162, tokenIndex162, depth162
			return false
		},
		/* 41 Nil <- <(('n' 'i' 'l') / '~')> */
		func() bool {
			position166, tokenIndex166, depth166 := position, tokenIndex, depth
			{
				position167 := position
				depth++
				{
					position168, tokenIndex168, depth168 := position, tokenIndex, depth
					if buffer[position] != rune('n') {
						goto l169
					}
					position++
					if buffer[position] != rune('i') {
						goto l169
					}
					position++
					if buffer[position] != rune('l') {
						goto l169
					}
					position++
					goto l168
				l169:
					position, tokenIndex, depth = position168, tokenIndex168, depth168
					if buffer[position] != rune('~') {
						goto l166
					}
					position++
				}
			l168:
				depth--
				add(ruleNil, position167)
			}
			return true
		l166:
			position, tokenIndex, depth = position166, tokenIndex166, depth166
			return false
		},
		/* 42 Undefined <- <('~' '~')> */
		func() bool {
			position170, tokenIndex170, depth170 := position, tokenIndex, depth
			{
				position171 := position
				depth++
				if buffer[position] != rune('~') {
					goto l170
				}
				position++
				if buffer[position] != rune('~') {
					goto l170
				}
				position++
				depth--
				add(ruleUndefined, position171)
			}
			return true
		l170:
			position, tokenIndex, depth = position170, tokenIndex170, depth170
			return false
		},
		/* 43 List <- <('[' Contents? ']')> */
		func() bool {
			position172, tokenIndex172, depth172 := position, tokenIndex, depth
			{
				position173 := position
				depth++
				if buffer[position] != rune('[') {
					goto l172
				}
				position++
				{
					position174, tokenIndex174, depth174 := position, tokenIndex, depth
					if !_rules[ruleContents]() {
						goto l174
					}
					goto l175
				l174:
					position, tokenIndex, depth = position174, tokenIndex174, depth174
				}
			l175:
				if buffer[position] != rune(']') {
					goto l172
				}
				position++
				depth--
				add(ruleList, position173)
			}
			return true
		l172:
			position, tokenIndex, depth = position172, tokenIndex172, depth172
			return false
		},
		/* 44 Contents <- <(Expression NextExpression*)> */
		func() bool {
			position176, tokenIndex176, depth176 := position, tokenIndex, depth
			{
				position177 := position
				depth++
				if !_rules[ruleExpression]() {
					goto l176
				}
			l178:
				{
					position179, tokenIndex179, depth179 := position, tokenIndex, depth
					if !_rules[ruleNextExpression]() {
						goto l179
					}
					goto l178
				l179:
					position, tokenIndex, depth = position179, tokenIndex179, depth179
				}
				depth--
				add(ruleContents, position177)
			}
			return true
		l176:
			position, tokenIndex, depth = position176, tokenIndex176, depth176
			return false
		},
		/* 45 Map <- <(CreateMap ws Assignments? '}')> */
		func() bool {
			position180, tokenIndex180, depth180 := position, tokenIndex, depth
			{
				position181 := position
				depth++
				if !_rules[ruleCreateMap]() {
					goto l180
				}
				if !_rules[rulews]() {
					goto l180
				}
				{
					position182, tokenIndex182, depth182 := position, tokenIndex, depth
					if !_rules[ruleAssignments]() {
						goto l182
					}
					goto l183
				l182:
					position, tokenIndex, depth = position182, tokenIndex182, depth182
				}
			l183:
				if buffer[position] != rune('}') {
					goto l180
				}
				position++
				depth--
				add(ruleMap, position181)
			}
			return true
		l180:
			position, tokenIndex, depth = position180, tokenIndex180, depth180
			return false
		},
		/* 46 CreateMap <- <'{'> */
		func() bool {
			position184, tokenIndex184, depth184 := position, tokenIndex, depth
			{
				position185 := position
				depth++
				if buffer[position] != rune('{') {
					goto l184
				}
				position++
				depth--
				add(ruleCreateMap, position185)
			}
			return true
		l184:
			position, tokenIndex, depth = position184, tokenIndex184, depth184
			return false
		},
		/* 47 Assignments <- <(Assignment (',' Assignment)*)> */
		func() bool {
			position186, tokenIndex186, depth186 := position, tokenIndex, depth
			{
				position187 := position
				depth++
				if !_rules[ruleAssignment]() {
					goto l186
				}
			l188:
				{
					position189, tokenIndex189, depth189 := position, tokenIndex, depth
					if buffer[position] != rune(',') {
						goto l189
					}
					position++
					if !_rules[ruleAssignment]() {
						goto l189
					}
					goto l188
				l189:
					position, tokenIndex, depth = position189, tokenIndex189, depth189
				}
				depth--
				add(ruleAssignments, position187)
			}
			return true
		l186:
			position, tokenIndex, depth = position186, tokenIndex186, depth186
			return false
		},
		/* 48 Assignment <- <(Expression '=' Expression)> */
		func() bool {
			position190, tokenIndex190, depth190 := position, tokenIndex, depth
			{
				position191 := position
				depth++
				if !_rules[ruleExpression]() {
					goto l190
				}
				if buffer[position] != rune('=') {
					goto l190
				}
				position++
				if !_rules[ruleExpression]() {
					goto l190
				}
				depth--
				add(ruleAssignment, position191)
			}
			return true
		l190:
			position, tokenIndex, depth = position190, tokenIndex190, depth190
			return false
		},
		/* 49 Merge <- <(RefMerge / SimpleMerge)> */
		func() bool {
			position192, tokenIndex192, depth192 := position, tokenIndex, depth
			{
				position193 := position
				depth++
				{
					position194, tokenIndex194, depth194 := position, tokenIndex, depth
					if !_rules[ruleRefMerge]() {
						goto l195
					}
					goto l194
				l195:
					position, tokenIndex, depth = position194, tokenIndex194, depth194
					if !_rules[ruleSimpleMerge]() {
						goto l192
					}
				}
			l194:
				depth--
				add(ruleMerge, position193)
			}
			return true
		l192:
			position, tokenIndex, depth = position192, tokenIndex192, depth192
			return false
		},
		/* 50 RefMerge <- <('m' 'e' 'r' 'g' 'e' !(req_ws Required) (req_ws (Replace / On))? req_ws Reference)> */
		func() bool {
			position196, tokenIndex196, depth196 := position, tokenIndex, depth
			{
				position197 := position
				depth++
				if buffer[position] != rune('m') {
					goto l196
				}
				position++
				if buffer[position] != rune('e') {
					goto l196
				}
				position++
				if buffer[position] != rune('r') {
					goto l196
				}
				position++
				if buffer[position] != rune('g') {
					goto l196
				}
				position++
				if buffer[position] != rune('e') {
					goto l196
				}
				position++
				{
					position198, tokenIndex198, depth198 := position, tokenIndex, depth
					if !_rules[rulereq_ws]() {
						goto l198
					}
					if !_rules[ruleRequired]() {
						goto l198
					}
					goto l196
				l198:
					position, tokenIndex, depth = position198, tokenIndex198, depth198
				}
				{
					position199, tokenIndex199, depth199 := position, tokenIndex, depth
					if !_rules[rulereq_ws]() {
						goto l199
					}
					{
						position201, tokenIndex201, depth201 := position, tokenIndex, depth
						if !_rules[ruleReplace]() {
							goto l202
						}
						goto l201
					l202:
						position, tokenIndex, depth = position201, tokenIndex201, depth201
						if !_rules[ruleOn]() {
							goto l199
						}
					}
				l201:
					goto l200
				l199:
					position, tokenIndex, depth = position199, tokenIndex199, depth199
				}
			l200:
				if !_rules[rulereq_ws]() {
					goto l196
				}
				if !_rules[ruleReference]() {
					goto l196
				}
				depth--
				add(ruleRefMerge, position197)
			}
			return true
		l196:
			position, tokenIndex, depth = position196, tokenIndex196, depth196
			return false
		},
		/* 51 SimpleMerge <- <('m' 'e' 'r' 'g' 'e' !'(' (req_ws (Replace / Required / On))?)> */
		func() bool {
			position203, tokenIndex203, depth203 := position, tokenIndex, depth
			{
				position204 := position
				depth++
				if buffer[position] != rune('m') {
					goto l203
				}
				position++
				if buffer[position] != rune('e') {
					goto l203
				}
				position++
				if buffer[position] != rune('r') {
					goto l203
				}
				position++
				if buffer[position] != rune('g') {
					goto l203
				}
				position++
				if buffer[position] != rune('e') {
					goto l203
				}
				position++
				{
					position205, tokenIndex205, depth205 := position, tokenIndex, depth
					if buffer[position] != rune('(') {
						goto l205
					}
					position++
					goto l203
				l205:
					position, tokenIndex, depth = position205, tokenIndex205, depth205
				}
				{
					position206, tokenIndex206, depth206 := position, tokenIndex, depth
					if !_rules[rulereq_ws]() {
						goto l206
					}
					{
						position208, tokenIndex208, depth208 := position, tokenIndex, depth
						if !_rules[ruleReplace]() {
							goto l209
						}
						goto l208
					l209:
						position, tokenIndex, depth = position208, tokenIndex208, depth208
						if !_rules[ruleRequired]() {
							goto l210
						}
						goto l208
					l210:
						position, tokenIndex, depth = position208, tokenIndex208, depth208
						if !_rules[ruleOn]() {
							goto l206
						}
					}
				l208:
					goto l207
				l206:
					position, tokenIndex, depth = position206, tokenIndex206, depth206
				}
			l207:
				depth--
				add(ruleSimpleMerge, position204)
			}
			return true
		l203:
			position, tokenIndex, depth = position203, tokenIndex203, depth203
			return false
		},
		/* 52 Replace <- <('r' 'e' 'p' 'l' 'a' 'c' 'e')> */
		func() bool {
			position211, tokenIndex211, depth211 := position, tokenIndex, depth
			{
				position212 := position
				depth++
				if buffer[position] != rune('r') {
					goto l211
				}
				position++
				if buffer[position] != rune('e') {
					goto l211
				}
				position++
				if buffer[position] != rune('p') {
					goto l211
				}
				position++
				if buffer[position] != rune('l') {
					goto l211
				}
				position++
				if buffer[position] != rune('a') {
					goto l211
				}
				position++
				if buffer[position] != rune('c') {
					goto l211
				}
				position++
				if buffer[position] != rune('e') {
					goto l211
				}
				position++
				depth--
				add(ruleReplace, position212)
			}
			return true
		l211:
			position, tokenIndex, depth = position211, tokenIndex211, depth211
			return false
		},
		/* 53 Required <- <('r' 'e' 'q' 'u' 'i' 'r' 'e' 'd')> */
		func() bool {
			position213, tokenIndex213, depth213 := position, tokenIndex, depth
			{
				position214 := position
				depth++
				if buffer[position] != rune('r') {
					goto l213
				}
				position++
				if buffer[position] != rune('e') {
					goto l213
				}
				position++
				if buffer[position] != rune('q') {
					goto l213
				}
				position++
				if buffer[position] != rune('u') {
					goto l213
				}
				position++
				if buffer[position] != rune('i') {
					goto l213
				}
				position++
				if buffer[position] != rune('r') {
					goto l213
				}
				position++
				if buffer[position] != rune('e') {
					goto l213
				}
				position++
				if buffer[position] != rune('d') {
					goto l213
				}
				position++
				depth--
				add(ruleRequired, position214)
			}
			return true
		l213:
			position, tokenIndex, depth = position213, tokenIndex213, depth213
			return false
		},
		/* 54 On <- <('o' 'n' req_ws Name)> */
		func() bool {
			position215, tokenIndex215, depth215 := position, tokenIndex, depth
			{
				position216 := position
				depth++
				if buffer[position] != rune('o') {
					goto l215
				}
				position++
				if buffer[position] != rune('n') {
					goto l215
				}
				position++
				if !_rules[rulereq_ws]() {
					goto l215
				}
				if !_rules[ruleName]() {
					goto l215
				}
				depth--
				add(ruleOn, position216)
			}
			return true
		l215:
			position, tokenIndex, depth = position215, tokenIndex215, depth215
			return false
		},
		/* 55 Auto <- <('a' 'u' 't' 'o')> */
		func() bool {
			position217, tokenIndex217, depth217 := position, tokenIndex, depth
			{
				position218 := position
				depth++
				if buffer[position] != rune('a') {
					goto l217
				}
				position++
				if buffer[position] != rune('u') {
					goto l217
				}
				position++
				if buffer[position] != rune('t') {
					goto l217
				}
				position++
				if buffer[position] != rune('o') {
					goto l217
				}
				position++
				depth--
				add(ruleAuto, position218)
			}
			return true
		l217:
			position, tokenIndex, depth = position217, tokenIndex217, depth217
			return false
		},
		/* 56 Mapping <- <('m' 'a' 'p' '[' Level7 (LambdaExpr / ('|' Expression)) ']')> */
		func() bool {
			position219, tokenIndex219, depth219 := position, tokenIndex, depth
			{
				position220 := position
				depth++
				if buffer[position] != rune('m') {
					goto l219
				}
				position++
				if buffer[position] != rune('a') {
					goto l219
				}
				position++
				if buffer[position] != rune('p') {
					goto l219
				}
				position++
				if buffer[position] != rune('[') {
					goto l219
				}
				position++
				if !_rules[ruleLevel7]() {
					goto l219
				}
				{
					position221, tokenIndex221, depth221 := position, tokenIndex, depth
					if !_rules[ruleLambdaExpr]() {
						goto l222
					}
					goto l221
				l222:
					position, tokenIndex, depth = position221, tokenIndex221, depth221
					if buffer[position] != rune('|') {
						goto l219
					}
					position++
					if !_rules[ruleExpression]() {
						goto l219
					}
				}
			l221:
				if buffer[position] != rune(']') {
					goto l219
				}
				position++
				depth--
				add(ruleMapping, position220)
			}
			return true
		l219:
			position, tokenIndex, depth = position219, tokenIndex219, depth219
			return false
		},
		/* 57 Sum <- <('s' 'u' 'm' '[' Level7 '|' Level7 (LambdaExpr / ('|' Expression)) ']')> */
		func() bool {
			position223, tokenIndex223, depth223 := position, tokenIndex, depth
			{
				position224 := position
				depth++
				if buffer[position] != rune('s') {
					goto l223
				}
				position++
				if buffer[position] != rune('u') {
					goto l223
				}
				position++
				if buffer[position] != rune('m') {
					goto l223
				}
				position++
				if buffer[position] != rune('[') {
					goto l223
				}
				position++
				if !_rules[ruleLevel7]() {
					goto l223
				}
				if buffer[position] != rune('|') {
					goto l223
				}
				position++
				if !_rules[ruleLevel7]() {
					goto l223
				}
				{
					position225, tokenIndex225, depth225 := position, tokenIndex, depth
					if !_rules[ruleLambdaExpr]() {
						goto l226
					}
					goto l225
				l226:
					position, tokenIndex, depth = position225, tokenIndex225, depth225
					if buffer[position] != rune('|') {
						goto l223
					}
					position++
					if !_rules[ruleExpression]() {
						goto l223
					}
				}
			l225:
				if buffer[position] != rune(']') {
					goto l223
				}
				position++
				depth--
				add(ruleSum, position224)
			}
			return true
		l223:
			position, tokenIndex, depth = position223, tokenIndex223, depth223
			return false
		},
		/* 58 Lambda <- <('l' 'a' 'm' 'b' 'd' 'a' (LambdaRef / LambdaExpr))> */
		func() bool {
			position227, tokenIndex227, depth227 := position, tokenIndex, depth
			{
				position228 := position
				depth++
				if buffer[position] != rune('l') {
					goto l227
				}
				position++
				if buffer[position] != rune('a') {
					goto l227
				}
				position++
				if buffer[position] != rune('m') {
					goto l227
				}
				position++
				if buffer[position] != rune('b') {
					goto l227
				}
				position++
				if buffer[position] != rune('d') {
					goto l227
				}
				position++
				if buffer[position] != rune('a') {
					goto l227
				}
				position++
				{
					position229, tokenIndex229, depth229 := position, tokenIndex, depth
					if !_rules[ruleLambdaRef]() {
						goto l230
					}
					goto l229
				l230:
					position, tokenIndex, depth = position229, tokenIndex229, depth229
					if !_rules[ruleLambdaExpr]() {
						goto l227
					}
				}
			l229:
				depth--
				add(ruleLambda, position228)
			}
			return true
		l227:
			position, tokenIndex, depth = position227, tokenIndex227, depth227
			return false
		},
		/* 59 LambdaRef <- <(req_ws Expression)> */
		func() bool {
			position231, tokenIndex231, depth231 := position, tokenIndex, depth
			{
				position232 := position
				depth++
				if !_rules[rulereq_ws]() {
					goto l231
				}
				if !_rules[ruleExpression]() {
					goto l231
				}
				depth--
				add(ruleLambdaRef, position232)
			}
			return true
		l231:
			position, tokenIndex, depth = position231, tokenIndex231, depth231
			return false
		},
		/* 60 LambdaExpr <- <(ws '|' ws Name NextName* ws '|' ws ('-' '>') Expression)> */
		func() bool {
			position233, tokenIndex233, depth233 := position, tokenIndex, depth
			{
				position234 := position
				depth++
				if !_rules[rulews]() {
					goto l233
				}
				if buffer[position] != rune('|') {
					goto l233
				}
				position++
				if !_rules[rulews]() {
					goto l233
				}
				if !_rules[ruleName]() {
					goto l233
				}
			l235:
				{
					position236, tokenIndex236, depth236 := position, tokenIndex, depth
					if !_rules[ruleNextName]() {
						goto l236
					}
					goto l235
				l236:
					position, tokenIndex, depth = position236, tokenIndex236, depth236
				}
				if !_rules[rulews]() {
					goto l233
				}
				if buffer[position] != rune('|') {
					goto l233
				}
				position++
				if !_rules[rulews]() {
					goto l233
				}
				if buffer[position] != rune('-') {
					goto l233
				}
				position++
				if buffer[position] != rune('>') {
					goto l233
				}
				position++
				if !_rules[ruleExpression]() {
					goto l233
				}
				depth--
				add(ruleLambdaExpr, position234)
			}
			return true
		l233:
			position, tokenIndex, depth = position233, tokenIndex233, depth233
			return false
		},
		/* 61 NextName <- <(ws ',' ws Name)> */
		func() bool {
			position237, tokenIndex237, depth237 := position, tokenIndex, depth
			{
				position238 := position
				depth++
				if !_rules[rulews]() {
					goto l237
				}
				if buffer[position] != rune(',') {
					goto l237
				}
				position++
				if !_rules[rulews]() {
					goto l237
				}
				if !_rules[ruleName]() {
					goto l237
				}
				depth--
				add(ruleNextName, position238)
			}
			return true
		l237:
			position, tokenIndex, depth = position237, tokenIndex237, depth237
			return false
		},
		/* 62 Name <- <([a-z] / [A-Z] / [0-9] / '_')+> */
		func() bool {
			position239, tokenIndex239, depth239 := position, tokenIndex, depth
			{
				position240 := position
				depth++
				{
					position243, tokenIndex243, depth243 := position, tokenIndex, depth
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l244
					}
					position++
					goto l243
				l244:
					position, tokenIndex, depth = position243, tokenIndex243, depth243
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l245
					}
					position++
					goto l243
				l245:
					position, tokenIndex, depth = position243, tokenIndex243, depth243
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l246
					}
					position++
					goto l243
				l246:
					position, tokenIndex, depth = position243, tokenIndex243, depth243
					if buffer[position] != rune('_') {
						goto l239
					}
					position++
				}
			l243:
			l241:
				{
					position242, tokenIndex242, depth242 := position, tokenIndex, depth
					{
						position247, tokenIndex247, depth247 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l248
						}
						position++
						goto l247
					l248:
						position, tokenIndex, depth = position247, tokenIndex247, depth247
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l249
						}
						position++
						goto l247
					l249:
						position, tokenIndex, depth = position247, tokenIndex247, depth247
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l250
						}
						position++
						goto l247
					l250:
						position, tokenIndex, depth = position247, tokenIndex247, depth247
						if buffer[position] != rune('_') {
							goto l242
						}
						position++
					}
				l247:
					goto l241
				l242:
					position, tokenIndex, depth = position242, tokenIndex242, depth242
				}
				depth--
				add(ruleName, position240)
			}
			return true
		l239:
			position, tokenIndex, depth = position239, tokenIndex239, depth239
			return false
		},
		/* 63 Reference <- <('.'? Key FollowUpRef)> */
		func() bool {
			position251, tokenIndex251, depth251 := position, tokenIndex, depth
			{
				position252 := position
				depth++
				{
					position253, tokenIndex253, depth253 := position, tokenIndex, depth
					if buffer[position] != rune('.') {
						goto l253
					}
					position++
					goto l254
				l253:
					position, tokenIndex, depth = position253, tokenIndex253, depth253
				}
			l254:
				if !_rules[ruleKey]() {
					goto l251
				}
				if !_rules[ruleFollowUpRef]() {
					goto l251
				}
				depth--
				add(ruleReference, position252)
			}
			return true
		l251:
			position, tokenIndex, depth = position251, tokenIndex251, depth251
			return false
		},
		/* 64 FollowUpRef <- <('.' (Key / Index))*> */
		func() bool {
			{
				position256 := position
				depth++
			l257:
				{
					position258, tokenIndex258, depth258 := position, tokenIndex, depth
					if buffer[position] != rune('.') {
						goto l258
					}
					position++
					{
						position259, tokenIndex259, depth259 := position, tokenIndex, depth
						if !_rules[ruleKey]() {
							goto l260
						}
						goto l259
					l260:
						position, tokenIndex, depth = position259, tokenIndex259, depth259
						if !_rules[ruleIndex]() {
							goto l258
						}
					}
				l259:
					goto l257
				l258:
					position, tokenIndex, depth = position258, tokenIndex258, depth258
				}
				depth--
				add(ruleFollowUpRef, position256)
			}
			return true
		},
		/* 65 Key <- <(([a-z] / [A-Z] / [0-9] / '_') ([a-z] / [A-Z] / [0-9] / '_' / '-')* (':' ([a-z] / [A-Z] / [0-9] / '_') ([a-z] / [A-Z] / [0-9] / '_' / '-')*)?)> */
		func() bool {
			position261, tokenIndex261, depth261 := position, tokenIndex, depth
			{
				position262 := position
				depth++
				{
					position263, tokenIndex263, depth263 := position, tokenIndex, depth
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l264
					}
					position++
					goto l263
				l264:
					position, tokenIndex, depth = position263, tokenIndex263, depth263
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l265
					}
					position++
					goto l263
				l265:
					position, tokenIndex, depth = position263, tokenIndex263, depth263
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l266
					}
					position++
					goto l263
				l266:
					position, tokenIndex, depth = position263, tokenIndex263, depth263
					if buffer[position] != rune('_') {
						goto l261
					}
					position++
				}
			l263:
			l267:
				{
					position268, tokenIndex268, depth268 := position, tokenIndex, depth
					{
						position269, tokenIndex269, depth269 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l270
						}
						position++
						goto l269
					l270:
						position, tokenIndex, depth = position269, tokenIndex269, depth269
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l271
						}
						position++
						goto l269
					l271:
						position, tokenIndex, depth = position269, tokenIndex269, depth269
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l272
						}
						position++
						goto l269
					l272:
						position, tokenIndex, depth = position269, tokenIndex269, depth269
						if buffer[position] != rune('_') {
							goto l273
						}
						position++
						goto l269
					l273:
						position, tokenIndex, depth = position269, tokenIndex269, depth269
						if buffer[position] != rune('-') {
							goto l268
						}
						position++
					}
				l269:
					goto l267
				l268:
					position, tokenIndex, depth = position268, tokenIndex268, depth268
				}
				{
					position274, tokenIndex274, depth274 := position, tokenIndex, depth
					if buffer[position] != rune(':') {
						goto l274
					}
					position++
					{
						position276, tokenIndex276, depth276 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l277
						}
						position++
						goto l276
					l277:
						position, tokenIndex, depth = position276, tokenIndex276, depth276
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l278
						}
						position++
						goto l276
					l278:
						position, tokenIndex, depth = position276, tokenIndex276, depth276
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l279
						}
						position++
						goto l276
					l279:
						position, tokenIndex, depth = position276, tokenIndex276, depth276
						if buffer[position] != rune('_') {
							goto l274
						}
						position++
					}
				l276:
				l280:
					{
						position281, tokenIndex281, depth281 := position, tokenIndex, depth
						{
							position282, tokenIndex282, depth282 := position, tokenIndex, depth
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l283
							}
							position++
							goto l282
						l283:
							position, tokenIndex, depth = position282, tokenIndex282, depth282
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l284
							}
							position++
							goto l282
						l284:
							position, tokenIndex, depth = position282, tokenIndex282, depth282
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l285
							}
							position++
							goto l282
						l285:
							position, tokenIndex, depth = position282, tokenIndex282, depth282
							if buffer[position] != rune('_') {
								goto l286
							}
							position++
							goto l282
						l286:
							position, tokenIndex, depth = position282, tokenIndex282, depth282
							if buffer[position] != rune('-') {
								goto l281
							}
							position++
						}
					l282:
						goto l280
					l281:
						position, tokenIndex, depth = position281, tokenIndex281, depth281
					}
					goto l275
				l274:
					position, tokenIndex, depth = position274, tokenIndex274, depth274
				}
			l275:
				depth--
				add(ruleKey, position262)
			}
			return true
		l261:
			position, tokenIndex, depth = position261, tokenIndex261, depth261
			return false
		},
		/* 66 Index <- <('[' [0-9]+ ']')> */
		func() bool {
			position287, tokenIndex287, depth287 := position, tokenIndex, depth
			{
				position288 := position
				depth++
				if buffer[position] != rune('[') {
					goto l287
				}
				position++
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l287
				}
				position++
			l289:
				{
					position290, tokenIndex290, depth290 := position, tokenIndex, depth
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l290
					}
					position++
					goto l289
				l290:
					position, tokenIndex, depth = position290, tokenIndex290, depth290
				}
				if buffer[position] != rune(']') {
					goto l287
				}
				position++
				depth--
				add(ruleIndex, position288)
			}
			return true
		l287:
			position, tokenIndex, depth = position287, tokenIndex287, depth287
			return false
		},
		/* 67 IP <- <([0-9]+ '.' [0-9]+ '.' [0-9]+ '.' [0-9]+)> */
		func() bool {
			position291, tokenIndex291, depth291 := position, tokenIndex, depth
			{
				position292 := position
				depth++
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l291
				}
				position++
			l293:
				{
					position294, tokenIndex294, depth294 := position, tokenIndex, depth
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l294
					}
					position++
					goto l293
				l294:
					position, tokenIndex, depth = position294, tokenIndex294, depth294
				}
				if buffer[position] != rune('.') {
					goto l291
				}
				position++
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l291
				}
				position++
			l295:
				{
					position296, tokenIndex296, depth296 := position, tokenIndex, depth
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l296
					}
					position++
					goto l295
				l296:
					position, tokenIndex, depth = position296, tokenIndex296, depth296
				}
				if buffer[position] != rune('.') {
					goto l291
				}
				position++
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l291
				}
				position++
			l297:
				{
					position298, tokenIndex298, depth298 := position, tokenIndex, depth
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l298
					}
					position++
					goto l297
				l298:
					position, tokenIndex, depth = position298, tokenIndex298, depth298
				}
				if buffer[position] != rune('.') {
					goto l291
				}
				position++
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l291
				}
				position++
			l299:
				{
					position300, tokenIndex300, depth300 := position, tokenIndex, depth
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l300
					}
					position++
					goto l299
				l300:
					position, tokenIndex, depth = position300, tokenIndex300, depth300
				}
				depth--
				add(ruleIP, position292)
			}
			return true
		l291:
			position, tokenIndex, depth = position291, tokenIndex291, depth291
			return false
		},
		/* 68 ws <- <(' ' / '\t' / '\n' / '\r')*> */
		func() bool {
			{
				position302 := position
				depth++
			l303:
				{
					position304, tokenIndex304, depth304 := position, tokenIndex, depth
					{
						position305, tokenIndex305, depth305 := position, tokenIndex, depth
						if buffer[position] != rune(' ') {
							goto l306
						}
						position++
						goto l305
					l306:
						position, tokenIndex, depth = position305, tokenIndex305, depth305
						if buffer[position] != rune('\t') {
							goto l307
						}
						position++
						goto l305
					l307:
						position, tokenIndex, depth = position305, tokenIndex305, depth305
						if buffer[position] != rune('\n') {
							goto l308
						}
						position++
						goto l305
					l308:
						position, tokenIndex, depth = position305, tokenIndex305, depth305
						if buffer[position] != rune('\r') {
							goto l304
						}
						position++
					}
				l305:
					goto l303
				l304:
					position, tokenIndex, depth = position304, tokenIndex304, depth304
				}
				depth--
				add(rulews, position302)
			}
			return true
		},
		/* 69 req_ws <- <(' ' / '\t' / '\n' / '\r')+> */
		func() bool {
			position309, tokenIndex309, depth309 := position, tokenIndex, depth
			{
				position310 := position
				depth++
				{
					position313, tokenIndex313, depth313 := position, tokenIndex, depth
					if buffer[position] != rune(' ') {
						goto l314
					}
					position++
					goto l313
				l314:
					position, tokenIndex, depth = position313, tokenIndex313, depth313
					if buffer[position] != rune('\t') {
						goto l315
					}
					position++
					goto l313
				l315:
					position, tokenIndex, depth = position313, tokenIndex313, depth313
					if buffer[position] != rune('\n') {
						goto l316
					}
					position++
					goto l313
				l316:
					position, tokenIndex, depth = position313, tokenIndex313, depth313
					if buffer[position] != rune('\r') {
						goto l309
					}
					position++
				}
			l313:
			l311:
				{
					position312, tokenIndex312, depth312 := position, tokenIndex, depth
					{
						position317, tokenIndex317, depth317 := position, tokenIndex, depth
						if buffer[position] != rune(' ') {
							goto l318
						}
						position++
						goto l317
					l318:
						position, tokenIndex, depth = position317, tokenIndex317, depth317
						if buffer[position] != rune('\t') {
							goto l319
						}
						position++
						goto l317
					l319:
						position, tokenIndex, depth = position317, tokenIndex317, depth317
						if buffer[position] != rune('\n') {
							goto l320
						}
						position++
						goto l317
					l320:
						position, tokenIndex, depth = position317, tokenIndex317, depth317
						if buffer[position] != rune('\r') {
							goto l312
						}
						position++
					}
				l317:
					goto l311
				l312:
					position, tokenIndex, depth = position312, tokenIndex312, depth312
				}
				depth--
				add(rulereq_ws, position310)
			}
			return true
		l309:
			position, tokenIndex, depth = position309, tokenIndex309, depth309
			return false
		},
	}
	p.rules = _rules
}
