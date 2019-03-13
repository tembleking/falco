

deploy: copy-credentials
	kubectl create configmap falco-config --from-file=falco-config
	kubectl create secret generic  google-data --from-file google-data
	kubectl apply -f falco-account.yaml 
	kubectl apply -f falco-service.yaml 
	kubectl apply -f falco-daemonset-configmap.yaml

clean:
	kubectl delete -f falco-account.yaml 
	kubectl delete -f falco-service.yaml 
	kubectl delete -f falco-daemonset-configmap.yaml
	kubectl delete configmap falco-config
	kubectl delete secret google-data

copy-credentials:
	cp ~/.config/gcloud/legacy_credentials/*/adc.json google-data/credentials-data
