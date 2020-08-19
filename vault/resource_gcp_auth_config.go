package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

func gcpAuthConfigResource() *schema.Resource {
	return &schema.Resource{

		Create: gcpAuthConfigureWrite,
		Update: gcpAuthConfigureWrite,
		Read:   gcpAuthConfigureRead,
		Delete: gcpAuthConfigureDelete,
		Exists: gcpAuthConfigureExists,

		Schema: map[string]*schema.Schema{
			"path": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "gcp",
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"credentials": {
				Type:         schema.TypeString,
				StateFunc:    NormalizeGCPCredentials,
				ValidateFunc: ValidateGCPCredentials,
				Sensitive:    true,
				Optional:     true,
			},
			"iam_alias": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"gce_alias": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"iam_metadata": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
				Computed: true,
			},
			"default_iam_metadata": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
			"gce_metadata": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional: true,
				Computed: true,
			},
			"default_gce_metadata": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},

			// Computed credentials attributes
			"client_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"private_key_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"project_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"client_email": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func ValidateGCPCredentials(configI interface{}, k string) ([]string, []error) {
	credentials := configI.(string)
	dataMap := map[string]interface{}{}
	err := json.Unmarshal([]byte(credentials), &dataMap)
	if err != nil {
		return nil, []error{err}
	}
	return nil, nil
}

func NormalizeGCPCredentials(configI interface{}) string {
	credentials := configI.(string)

	dataMap := map[string]interface{}{}
	err := json.Unmarshal([]byte(credentials), &dataMap)
	if err != nil {
		// The validate function should've taken care of this.
		log.Printf("[ERROR] Invalid JSON data in vault_gcp_auth_backend: %s", err)
		return ""
	}

	ret, err := json.Marshal(dataMap)
	if err != nil {
		// Should never happen.
		log.Printf("[ERROR] Problem normalizing JSON for vault_gcp_auth_backend: %s", err)
		return credentials
	}

	return string(ret)
}

func gcpAuthBackendConfigPath(path string) string {
	return "auth/" + strings.Trim(path, "/") + "/config"
}

func gcpAuthConfigureWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	id := d.Get("path").(string)
	d.SetId(id)

	path := gcpAuthBackendConfigPath(d.Id())
	data := map[string]interface{}{}

	if v, ok := d.GetOk("credentials"); ok {
		data["credentials"] = v.(string)
	}

	if v, ok := d.GetOk("iam_alias"); ok {
		data["iam_alias"] = v.(string)
	}
	if v, ok := d.GetOk("gce_alias"); ok {
		data["gce_alias"] = v.(string)
	}

	iamMetadata := d.Get("iam_metadata").(*schema.Set).List()
	defaultIamMetadata := d.Get("default_iam_metadata").(bool)
	if defaultIamMetadata {
		data["iam_metadata"] = "default"
	} else {
		data["iam_metadata"] = iamMetadata
	}

	gceMetadata := d.Get("gce_metadata").(*schema.Set).List()
	defaultGceMetadata := d.Get("default_gce_metadata").(bool)
	if defaultGceMetadata {
		data["gce_metadata"] = "default"
	} else {
		data["gce_metadata"] = gceMetadata
	}

	log.Printf("[DEBUG] Writing GCP Auth config %q", path)
	_, err := client.Logical().Write(path, data)

	if err != nil {
		d.SetId("")
		return fmt.Errorf("error writing GCP Auth config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote GCP Auth config %q", path)

	return gcpAuthConfigureRead(d, meta)
}

func gcpAuthConfigureRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := gcpAuthBackendConfigPath(d.Id())

	log.Printf("[DEBUG] Reading GCP Auth config %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading GCP Auth config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read GCP Auth config %q", path)

	if resp == nil {
		log.Printf("[WARN] GCP Auth config %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	for _, k := range []string{"credentials", "iam_alias", "gce_alias", "iam_metadata", "gce_metadata", "private_key_id", "client_id", "project_id", "client_email"} {
		v, ok := resp.Data[k]
		if ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error setting %s for GCP Auth config %q: %q", k, path, err)
			}
		}
	}

	return nil
}

func gcpAuthConfigureDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := gcpAuthBackendConfigPath(d.Id())

	log.Printf("[DEBUG] Resetting GCP Auth config %q", path)

	data := map[string]interface{}{}
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error resetting GCP Auth config %q: %q", path, err)
	}
	log.Printf("[DEBUG] Reset GCP Auth config %q", path)

	return nil
}

func gcpAuthConfigureExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	path := gcpAuthBackendConfigPath(d.Id())

	log.Printf("[DEBUG] Checking if GCP Auth config %q exists", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking for existence of GCP Auth config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if GCP Auth config %q exists", path)

	return resp != nil, nil
}
