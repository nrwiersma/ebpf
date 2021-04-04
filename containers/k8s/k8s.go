package k8s

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nrwiersma/ebpf/containers"
	"inet.af/netaddr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

type endpointKey struct {
	IP   [16]byte
	Port uint16
}

// Service is a kubernetes container service.
type Service struct {
	node       string
	ignoreNS   []string
	cgroupRoot string

	events chan containers.ContainerEvent

	// TODO: This should be switched for something with a faster
	//		 read path. Perhaps iradix.
	mu    sync.RWMutex
	names map[[16]byte]string

	doneCh chan struct{}
}

// New returns a kuberenetes container service.
func New(node, cgroupRoot string, ignoreNs []string) (*Service, error) {
	path := os.Getenv("KUBECONFIG")
	cfg, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		return nil, err
	}

	client, err := k8s.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	return NewWithClient(client, node, cgroupRoot, ignoreNs)
}

// NewWithClient returns a kuberenetes container service using the
// given kubernetes client.
func NewWithClient(client *k8s.Clientset, node, cgroupRoot string, ignoreNs []string) (*Service, error) {
	svc := &Service{
		node:       node,
		ignoreNS:   ignoreNs,
		cgroupRoot: cgroupRoot,
		events:     make(chan containers.ContainerEvent, 100),
		names:      map[[16]byte]string{},
		doneCh:     make(chan struct{}),
	}

	fac := informers.NewSharedInformerFactory(client, time.Minute)
	fac.Core().V1().Pods().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    svc.onAddPod(),
		UpdateFunc: svc.onUpdatePod(),
		DeleteFunc: svc.onDeletePod(),
	})
	fac.Core().V1().Services().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    svc.onAddPod(),
		UpdateFunc: svc.onUpdatePod(),
		DeleteFunc: svc.onDeletePod(),
	})

	go fac.Start(svc.doneCh)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for typ, ok := range fac.WaitForCacheSync(ctx.Done()) {
		if !ok {
			return nil, fmt.Errorf("could not sync k8s object caches for %q", typ)
		}
	}

	return svc, nil
}

func (s *Service) onAddPod() func(obj interface{}) {
	return func(obj interface{}) {
		switch v := obj.(type) {
		case *corev1.Pod:
			pod := v
			name := pod.Namespace + "/" + pod.Name

			s.addName(pod.Status.PodIP, name)

			if !s.shouldEmit(pod) || pod.Status.Phase != corev1.PodRunning {
				return
			}

			s.events <- containers.ContainerEvent{
				Type:       containers.Added,
				Name:       name,
				CGroupPath: cgroupPath(s.cgroupRoot, pod),
			}

		case *corev1.Service:
			svc := v
			name := svc.Namespace + "/" + svc.Name

			s.addName(svc.Spec.ClusterIP, name)
		}
	}
}

func (s *Service) onUpdatePod() func(oldObj, newObj interface{}) {
	return func(oldObj, newObj interface{}) {
		switch v := newObj.(type) {
		case *corev1.Pod:
			newPod := v
			oldPod := oldObj.(*corev1.Pod)
			name := newPod.Namespace + "/" + newPod.Name

			if newPod.Status.PodIP != oldPod.Status.PodIP {
				s.removeName(oldPod.Status.PodIP)
				s.addName(newPod.Status.PodIP, name)
			}

			if !s.shouldEmit(newPod) {
				return
			}

			evnt := containers.ContainerEvent{
				Name:       name,
				CGroupPath: cgroupPath(s.cgroupRoot, newPod),
			}

			switch newPod.Status.Phase {
			case corev1.PodPending:
				return
			case corev1.PodRunning:
				evnt.Type = containers.Added
			default:
				evnt.Type = containers.Removed
			}

			s.events <- evnt

		case *corev1.Service:
			newSvc := v
			oldSvc := oldObj.(*corev1.Service)
			name := newSvc.Namespace + "/" + newSvc.Name

			if newSvc.Spec.ClusterIP == oldSvc.Spec.ClusterIP {
				return
			}

			s.removeName(oldSvc.Spec.ClusterIP)
			s.addName(newSvc.Spec.ClusterIP, name)
		}
	}
}

func (s *Service) onDeletePod() func(obj interface{}) {
	return func(obj interface{}) {
		switch v := obj.(type) {
		case *corev1.Pod:
			pod := v

			s.removeName(pod.Status.PodIP)

			if !s.shouldEmit(pod) {
				return
			}

			s.events <- containers.ContainerEvent{
				Type:       containers.Removed,
				Name:       pod.Namespace + "/" + pod.Name,
				CGroupPath: cgroupPath(s.cgroupRoot, pod),
			}

		case *corev1.Service:
			svc := v

			s.removeName(svc.Spec.ClusterIP)
		}
	}
}

func (s *Service) shouldEmit(pod *corev1.Pod) bool {
	if pod.Spec.NodeName != s.node {
		return false
	}

	for _, ns := range s.ignoreNS {
		if pod.Namespace == ns {
			return false
		}
	}

	return true
}

func (s *Service) addName(ip, name string) {
	if ip == "" {
		return
	}

	ipb := ipToBytes(ip)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.names[ipb] = name
}

func (s *Service) removeName(ip string) {
	if ip == "" {
		return
	}

	ipb := ipToBytes(ip)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.names, ipb)

}

func ipToBytes(v string) [16]byte {
	ip, err := netaddr.ParseIP(v)
	if err != nil {
		return [16]byte{}
	}

	return ip.As16()
}

// Events returns a channel of pod events.
func (s *Service) Events() <-chan containers.ContainerEvent {
	return s.events
}

// Name resolves an IP and port combination into a pod name.
func (s *Service) Name(ip [16]byte) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if name, ok := s.names[ip]; ok {
		return name
	}

	return netaddr.IPFrom16(ip).String()
}

// Close closes the container service.
func (s *Service) Close() error {
	close(s.doneCh)
	close(s.events)

	return nil
}

func cgroupPath(root string, pod *corev1.Pod) string {
	return fmt.Sprintf("%s/kubepods/%s/pod%s", root, strings.ToLower(string(pod.Status.QOSClass)), string(pod.UID))
}
