package helm

import (
	"errors"
	"time"

	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"

	"github.com/argoproj/argo-cd/util/repo"
)

var repoCache = cache.New(5*time.Minute, 5*time.Minute)

func NewRepo(url, name, username, password string, caData, certData, keyData []byte) (repo.Repo, error) {

	if name == "" {
		return nil, errors.New("must name repo")
	}

	cached, found := repoCache.Get(url)
	if found {
		log.WithFields(log.Fields{"url": url}).Debug("helm repo cache hit")
		return cached.(repo.Repo), nil
	}

	cmd, err := newCmd(repo.TempRepoPath(url))
	if err != nil {
		return nil, err
	}

	_, err = cmd.init()
	if err != nil {
		return nil, err
	}

	r := helmRepo{
		cmd:      cmd,
		url:      url,
		name:     name,
		username: username,
		password: password,
		caData:   caData,
		certData: certData,
		keyData:  keyData,
	}

	_, err = r.getIndex()
	if err != nil {
		return nil, err
	}

	_, err = r.repoAdd()
	if err != nil {
		return nil, err
	}

	_, err = r.cmd.repoUpdate()

	repoCache.Set(url, r, cache.DefaultExpiration)

	return r, err
}
