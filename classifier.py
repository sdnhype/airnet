import copy, pdb

#####################################################################
# NOTE:
# classifiers is intended to be used by the runtime
# policies composition is not supported here (Here is compilation!)
#####################################################################

class Rule(object):
    """
    A rule contains a filter and the parallel composition of zero or more
    actions.
    """
    def __init__(self, m, t, acts):
        self.match = m
        self.label = t
        self.actions = acts
        
class FabricRule(object):
    def __init__(self, f, acts, via_list):
        self.flow = f
        self.actions = acts
        self.via_list = via_list

    
class Classifier(object):
    """
    A classifier contains a list of rules, where the order of the list implies
    the relative priorities of the rules. 
    """
    
    def __init__(self, rules=[]):
        self.rules = list(rules)
        
    def append(self, item):
        if isinstance(item, Rule):
            self.rules.append(item)
        elif isinstance(item, Classifier):
            self.rules.extend(item.rules)
        else:
            raise TypeError
   
    def __add__(c1, c2):
        from language import identity, drop, forward, DataFctPolicy
        def _cross(r1, r2):
            """
            here DataFct need no special treatement
            if i have two DataFct that apply on the same flow
            i need to do function chaining (but the order is not important because )
            """
            
            intersection = r1.match.intersec(r2.match)      
            if intersection != drop:
                # label composition
                label = identity
                if r1.label is not identity and r2.label is not identity:
                    if r1.match.covers(r2.match):
                        label = r2.label # we use the more specific label
                    elif r2.match.covers(r1.match):
                        label = r1.label
                    else:
                        part1 = str(r1.label)
                        part2 = str(r2.label)
                        errorMsg = "tag intersection error: " + part1 + " and " + part2
                        raise AssertionError(errorMsg)
                else:    
                    if r1.label is identity:
                        label = r2.label
                    else:
                        label = r1.label
                #####
                # if they have the same forward action, we use only one
                # we assume that they have the same forward destination
                actions = set()
                contain_forward = False
                for a1 in r1.actions:
                    if isinstance(a1, forward):
                        contain_forward = True
                    actions.add(a1)
                        
                for a2 in r2.actions:
                    if isinstance(a2, forward) and not contain_forward:
                        actions.add(a2)
                    elif isinstance(a2, DataFctPolicy):
                        nwFct_added = False
                        for act in actions:
                            if isinstance(act, DataFctPolicy):
                                nwFct_added = True
                                act.add_parallel_fct(a2)
                        if not nwFct_added:
                            actions.add(a2)
                    elif not isinstance(a2, forward):
                        actions.add(a2)
                    else:
                        return None
                
                #actions = r1.actions | r2.actions  i will have rule with 2 forward actions to same destination
                return Rule(intersection, label, actions) 
            else:
                return None

        c3 = Classifier()
        for r1 in c1.rules:
            for r2 in c2.rules:
                crossed_r = _cross(r1, r2)
                if crossed_r:
                    c3.append(crossed_r) # je rajoute les regles d'intersection
                    # sachant que dans chaque classifier y a (identity, identity, set())
                    # donc toutes les regles des deux classifier seront rajoute
        if len(c3.rules) == 0:
            c3.append(Rule(identity, identity, set())) # je drop tout
        else:
            c3 = c3.optimize()
        return c3
    
    def __rshift__(c1, c2):
        from language import identity, DataFctPolicy, DynamicPolicy, modify, forward, tag, NetworkFunction
        from language import drop, match
        def _sequence_actions(a1, as2):
            if isinstance(a1, DataFctPolicy):
                a1.add_seq_actions(as2)
                return {a1}
            elif a1 == identity:
                return copy.copy(as2)
            elif isinstance(a1, modify):
                new_actions = set()
                for a2 in as2:
                    # DataFct or DyControl
                    if isinstance(a2, NetworkFunction):
                        new_actions.add(a1)
                        new_actions.add(a2)
                    elif isinstance(a2, forward):
                        new_actions.add(a1)
                        new_actions.add(a2)
                    elif a2 == identity:
                        new_actions.add(a1)
                    elif isinstance(a2, modify):
                        new_a1 = modify(**a1.map.copy())
                        new_a1.map.update(a2.map)
                        new_actions.add(new_a1)
                    else:
                        raise TypeError   
                return new_actions
            elif isinstance(a1, forward) or isinstance(a1, DynamicPolicy):
                # no right shift after a forward or a dynamic control function
                raise AssertionError
            else:
                raise TypeError
                    
        
        def _commute_test(act, pkts):
            """
            given a test b and an action p, return a test
            b' such that p >> b == b' >> p.
            e.g. (match1, tag1, actions1) >> (match2, tag2, actions2)
            match2 don't apply directly on match1 
            but apply on it after the execution of actions1
            """
            # if act == identity or isinstance(act, tag) --> deleted
            if act == identity:
                return pkts
            elif isinstance(act, DataFctPolicy):
                return identity
            elif isinstance(act, modify):
                new_match_dict = {}
                if pkts == identity:
                    return identity
                elif pkts == drop:
                    return drop 
                for f, v in pkts.map.iteritems():
                    if f in act.map and act.map[f] == v:
                        continue
                    elif f in act.map and act.map[f] != v:
                        # >> modify(srctcp=20) >> match (srctcp=30) ! 
                        # So the result is set() !
                        return drop  
                    else:
                        new_match_dict[f] = v
                if len(new_match_dict) == 0:
                    return identity
                return match(**new_match_dict)
            elif isinstance(act, forward):
                # no actions after a forward action !
                raise AssertionError
            else:
                raise TypeError 
        
        
        def _cross_act(r1, act, r2):
            # match
            m = r1.match.intersec(_commute_test(act, r2.match))
            # label
            # seq composition: if the second rule has a label, use it!
            label = r1.label
            if r2.label != identity:
                label = r2.label
            # actions
            actions = _sequence_actions(act, r2.actions)
            if m == drop:
                return None
            else:
                return Classifier([Rule(m, label, actions)])
    
        
        """
        cross two rules and return & non-total classifier
        """
        def _cross(r1, r2):            
            c = None
            for act in r1.actions:
                cross = _cross_act(r1, act, r2)
                if c is None:
                    c = cross
                elif not cross is None:
                    c_tmp = c + cross
                    c_tmp.append(c)
                    c_tmp.append(cross)
                    c = c_tmp
                    c.optimize()
            return c
        
        # composition logic start here
        c3 = Classifier()
        for r1 in c1.rules:
            if len(r1.actions) == 0: # len({identity}) == 1, drop == 0
                c3.append(r1)
            else:
                for r2 in c2.rules:
                    c_tmp = _cross(r1, r2) 
                    if not c_tmp is None:
                        c3.append(c_tmp)
        c3.optimize()
        return c3
    
    def optimize(self):
        return self.remove_shadowed_cover_single()
    
    def remove_shadowed_cover_single(self):
        opt_c = Classifier()
        for r in self.rules:
            if not reduce(lambda acc, new_r: acc or
                          new_r.match.covers(r.match),
                          opt_c.rules,
                          False):
            # si aucune regle ne couvre "r", je place "r" dans la cls optimise
                opt_c.rules.append(r)
        return opt_c
   
   

class FabricClassifier(object):
    """
    """
    def __init__(self, rules=[]):
        self.rules = list(rules)
        
    def append(self, item):
        if isinstance(item, FabricRule):
            self.rules.append(item)
        elif isinstance(item, FabricClassifier):
            self.rules.extend(item.rules)
        else:
            raise TypeError
    
    def __add__(c1, c2):
        c3 = FabricClassifier()
        c3.append(c1)
        c3.append(c2)
        return c3
        
    def __rshift__(c1, c2):
        from language import identity
        c3 = FabricClassifier()
        for r1 in c1.rules:
            new_actions = set()
            via_list = list()
            for r2 in c2.rules:
                flow = r1.flow
                for act1 in r1.actions:
                    if act1 != identity:
                        new_actions.add(act1)
                for act2 in r2.actions:
                    if act2 != identity:
                        new_actions.add(act2)
                for dm in r1.via_list:
                    via_list.append(dm)
                for dm in r2.via_list:
                    via_list.append(dm)
                c3.append(FabricRule(flow, new_actions, via_list)) 
        return c3        
