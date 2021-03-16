package k8s

import (
	"fmt"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type EventType int

const (
	NewPodEvent EventType = iota
	DeletePodEvent
)

type Event struct {
	Type        EventType
	Name        string
	Namespace   string
	FullName    string
	PodUID      string
	PodQOSClass string
}

func WatchPodEvents(events chan Event, quit <-chan struct{}) error {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}

	// watch new pod events
	source := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), string(v1.ResourcePods), v1.NamespaceAll, fields.Everything())
	_, k8sController := cache.NewInformer(
		source,
		&v1.Pod{},
		1*time.Minute,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    onAdd(events),
			UpdateFunc: onUpdate(events),
			DeleteFunc: onDelete(events),
		},
	)

	go k8sController.Run(quit)

	return nil
}

func onAdd(events chan Event) func(obj interface{}) {
	return func(obj interface{}) {
		pod, ok := obj.(*v1.Pod)
		if !ok {
			return
		}

		events <- Event{
			Type:        NewPodEvent,
			Name:        pod.Name,
			Namespace:   pod.Namespace,
			FullName:    pod.Name + "/" + pod.Namespace,
			PodUID:      string(pod.UID),
			PodQOSClass: string(pod.Status.QOSClass),
		}
		return
	}
}

func onUpdate(_ chan Event) func(oldObj, newObj interface{}) {
	return func(oldObj, newObj interface{}) {
		// do nothing
		return
	}
}

func onDelete(events chan Event) func(obj interface{}) {
	return func(obj interface{}) {
		pod, ok := obj.(*v1.Pod)
		if !ok {
			return
		}

		events <- Event{
			Type:        DeletePodEvent,
			Name:        pod.Name,
			Namespace:   pod.Namespace,
			FullName:    pod.Name + "/" + pod.Namespace,
			PodUID:      string(pod.UID),
			PodQOSClass: string(pod.Status.QOSClass),
		}
		return
	}
}

func GetCGroupPath(root, uid, qosClass string) string {
	return fmt.Sprintf("%s/kubepods/%s/pod%s", root, strings.ToLower(qosClass), uid)
}