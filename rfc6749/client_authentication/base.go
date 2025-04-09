package clientauth

type BaseHandler struct {
	store ClientStore
}

func (h *BaseHandler) SetClientStore(store ClientStore) {
	h.store = store
}

func (h *BaseHandler) MustClientStore(store ClientStore) error {
	if store == nil {
		return ErrNilClientStore
	}

	h.SetClientStore(store)
	return nil
}
