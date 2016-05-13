package password

import (
	"github.com/cloudfoundry-incubator/spiff/yaml"
)

func update(src,dst yaml.Node) (yaml.Node, bool) {
	switch s:=src.Value().(type) {
		case map[string]yaml.Node:
			if dst==nil {
				return updateMap(s,nil)
			}
			d,ok:=dst.Value().(map[string]yaml.Node)
			if !ok {
				d=nil
			}
			return updateMap(s,d)
		case []yaml.Node:
			if dst==nil {
				return updateList(s,nil)
			}
			d,ok:=dst.Value().([]yaml.Node)
			if ok {
				d=nil
			}
			return updateList(s,d)
		default:
			if src.Value()==REDACTED {
				if dst!=nil {
					return dst,false
				} else {
					src = createPassword()
				}
			}
			return src, true
	}
}

func updateMap(src,dst map[string]yaml.Node) (yaml.Node, bool) {
	modified:=false
	result:=map[string]yaml.Node{}
	for k, s := range src {
		d, ok := dst[k]
		if !ok {
			d=nil
		}
		n,m:=update(s,d)
		if m {
			modified=true
		}
		result[k]=n
	}
	return yaml.NewNode(result,""), modified
}

func updateList(src,dst []yaml.Node) (yaml.Node, bool) {
	modified:=false
	result:=make([]yaml.Node,len(src))
	for i, s := range src {
		var d yaml.Node
		if len(dst)<=i {
			d=nil
		} else {
			d=dst[i]
		}
		n,m:=update(s,d)
		if m {
			modified=true
		}
		result[i]=n
	}
	return yaml.NewNode(result,""), modified
}



func mapNode(n yaml.Node) yaml.Node {
	switch v:=n.Value().(type) {
		case map[string]yaml.Node:
			return mapMap(v)
		case []yaml.Node:
			return mapList(v)
		default:
			return yaml.NewNode(REDACTED,"")
	}
}

func mapMap(m map[string]yaml.Node) yaml.Node {
	result:=map[string]yaml.Node{}
	for k, n := range m {
		result[k]=mapNode(n)
	}
	return yaml.NewNode(result,"")
}

func mapList(l []yaml.Node) yaml.Node {
	result:=make([]yaml.Node,len(l))
	for i, n := range l {
		result[i]=mapNode(n)
	}
	return yaml.NewNode(result,"")
}